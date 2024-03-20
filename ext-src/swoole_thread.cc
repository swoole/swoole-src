/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"

#ifdef SW_THREAD

#include <sys/ipc.h>
#include <sys/resource.h>

#include <thread>

#include "swoole_lock.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_arginfo.h"
END_EXTERN_C()

using swoole::RWLock;

zend_class_entry *swoole_thread_ce;
static zend_object_handlers swoole_thread_handlers;

zend_class_entry *swoole_thread_map_ce;
static zend_object_handlers swoole_thread_map_handlers;

zend_class_entry *swoole_thread_arraylist_ce;
static zend_object_handlers swoole_thread_arraylist_handlers;

static void thread_map_value_dtor(zval *pDest);

struct MapItem {
    uint32_t type;
    uint32_t length;
    zend_string *key;
    union {
        char *strval;
        zend_long lval;
        double dval;
    };

    MapItem(zval *zvalue) {
        key = nullptr;
        strval = nullptr;
        store(zvalue);
    }

    void store(zval *zvalue) {
        type = Z_TYPE_P(zvalue);
        switch (type) {
        case IS_LONG:
            lval = zval_get_long(zvalue);
            break;
        case IS_DOUBLE:
            dval = zval_get_double(zvalue);
            break;
        case IS_STRING: {
            strval = swoole_strndup(Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
            length = Z_STRLEN_P(zvalue);
            break;
        }
        default:
            type = IS_LONG;
            lval = 0;
            break;
        }
    }

    void assign(zval *zvalue) {
        release();
        store(zvalue);
    }

    void fetch(zval *return_value) {
        switch (type) {
        case IS_LONG:
            RETVAL_LONG(lval);
            break;
        case IS_DOUBLE:
            RETVAL_LONG(dval);
            break;
        case IS_STRING:
            RETVAL_STRINGL(strval, length);
            break;
        default:
            RETVAL_NULL();
            break;
        }
    }

    void release() {
        if (type == IS_STRING) {
            sw_free(strval);
            strval = nullptr;
        }
    }

    ~MapItem() {
        if (strval) {
            release();
        }
        if (key) {
            zend_string_release(key);
        }
    }
};

struct Resource {
    RWLock lock_;
    uint32_t ref_count;

    Resource() : lock_(0) {
        ref_count = 1;
    }

    uint32_t add_ref() {
        return ++ref_count;
    }

    uint32_t del_ref() {
        return --ref_count;
    }
};

struct Map : public Resource {
    uint8_t type_;
    zend_array ht;

    enum KeyType {
        KEY_INT = 1,
        KEY_STR = 2,
    };

    Map(uint8_t type) : Resource() {
        type_ = type;
        zend_hash_init(&ht, 0, NULL, thread_map_value_dtor, 1);
    }

    ~Map() {
        zend_hash_destroy(&ht);
    }
};

struct ArrayList : public Resource {
    std::vector<MapItem *> list_;

    ArrayList() : Resource() {}

    ~ArrayList() {
        for (auto &value : list_) {
            delete value;
        }
    }

    bool exists(zend_long index) {
        return index < (zend_long) list_.size();
    }
};

typedef std::thread Thread;

struct MapHandlers {
    void (*offsetGet)(Map *map, zval *zkey, zval *return_value);
    void (*offsetExists)(Map *map, zval *zkey, zval *return_value);
    void (*offsetUnset)(Map *map, zval *zkey);
    void (*offsetSet)(Map *map, zval *zkey, zval *zvalue);
    void (*count)(Map *map, zval *return_value);
};

struct ThreadObject {
    Thread *thread;
    zend_object std;
};

struct ThreadMapObject {
    MapHandlers *handlers;
    Map *map;
    zend_object std;
};

struct ThreadArrayListObject {
    ArrayList *resource;
    zend_object std;
};

static void php_swoole_thread_join(zend_object *object);
static void thread_map_strkey_offsetGet(Map *map, zval *zkey, zval *return_value);
static void thread_map_strkey_offsetExists(Map *map, zval *zkey, zval *return_value);
static void thread_map_strkey_offsetUnset(Map *map, zval *zkey);
static void thread_map_strkey_offsetSet(Map *map, zval *zkey, zval *zvalue);

static void thread_map_intkey_offsetGet(Map *map, zval *zkey, zval *return_value);
static void thread_map_intkey_offsetExists(Map *map, zval *zkey, zval *return_value);
static void thread_map_intkey_offsetUnset(Map *map, zval *zkey);
static void thread_map_intkey_offsetSet(Map *map, zval *zkey, zval *zvalue);

static void thread_map_count(Map *map, zval *return_value);

thread_local zval thread_argv;
static std::mutex thread_lock;
static zend_long thread_resource_id = 0;
static std::unordered_map<uint32_t, void *> thread_resources;

MapHandlers map_intkey_handlers = {
    thread_map_intkey_offsetGet,
    thread_map_intkey_offsetExists,
    thread_map_intkey_offsetUnset,
    thread_map_intkey_offsetSet,
    thread_map_count,
};

MapHandlers map_strkey_handlers = {
    thread_map_strkey_offsetGet,
    thread_map_strkey_offsetExists,
    thread_map_strkey_offsetUnset,
    thread_map_strkey_offsetSet,
    thread_map_count,
};

static sw_inline ThreadObject *php_swoole_thread_fetch_object(zend_object *obj) {
    return (ThreadObject *) ((char *) obj - swoole_thread_handlers.offset);
}

static void php_swoole_thread_free_object(zend_object *object) {
    php_swoole_thread_join(object);
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_thread_create_object(zend_class_entry *ce) {
    ThreadObject *to = (ThreadObject *) zend_object_alloc(sizeof(ThreadObject), ce);
    zend_object_std_init(&to->std, ce);
    object_properties_init(&to->std, ce);
    to->std.handlers = &swoole_thread_handlers;
    return &to->std;
}

static void php_swoole_thread_join(zend_object *object) {
    ThreadObject *to = php_swoole_thread_fetch_object(object);
    if (to->thread && to->thread->joinable()) {
        to->thread->join();
        delete to->thread;
        to->thread = nullptr;
    }
}

static sw_inline ThreadMapObject *thread_map_fetch_object(zend_object *obj) {
    return (ThreadMapObject *) ((char *) obj - swoole_thread_map_handlers.offset);
}

static sw_inline zend_long thread_map_get_resource_id(zend_object *obj) {
    zval rv, *property = zend_read_property(swoole_thread_map_ce, obj, ZEND_STRL("id"), 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static sw_inline zend_long thread_map_get_resource_id(zval *zobject) {
    return thread_map_get_resource_id(Z_OBJ_P(zobject));
}

static void thread_map_free_object(zend_object *object) {
    zend_long resource_id = thread_map_get_resource_id(object);
    ThreadMapObject *mo = thread_map_fetch_object(object);
    if (mo->map) {
        thread_lock.lock();
        if (mo->map->del_ref() == 0) {
            thread_resources.erase(resource_id);
            delete mo->map;
            mo->map = nullptr;
        }
        thread_lock.unlock();
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_map_create_object(zend_class_entry *ce) {
    ThreadMapObject *mo = (ThreadMapObject *) zend_object_alloc(sizeof(ThreadMapObject), ce);
    zend_object_std_init(&mo->std, ce);
    object_properties_init(&mo->std, ce);
    mo->std.handlers = &swoole_thread_map_handlers;
    return &mo->std;
}

ThreadMapObject *thread_map_fetch_object_check(zval *zobject) {
    ThreadMapObject *map = thread_map_fetch_object(Z_OBJ_P(zobject));
    if (!map->map) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return map;
}

static void thread_map_strkey_offsetGet(Map *map, zval *zkey, zval *return_value) {
    zend::String skey(zkey);
    map->lock_.lock_rd();
    MapItem *tv = (MapItem *) zend_hash_find_ptr(&map->ht, skey.get());
    if (tv) {
        tv->fetch(return_value);
    }
    map->lock_.unlock();
}

static void thread_map_strkey_offsetExists(Map *map, zval *zkey, zval *return_value) {
    zend::String skey(zkey);
    map->lock_.lock_rd();
    RETVAL_BOOL(zend_hash_find_ptr(&map->ht, skey.get()) != NULL);
    map->lock_.unlock();
}

static void thread_map_strkey_offsetUnset(Map *map, zval *zkey) {
    zend::String skey(zkey);
    map->lock_.lock();
    zend_hash_del(&map->ht, skey.get());
    map->lock_.unlock();
}

static void thread_map_strkey_offsetSet(Map *map, zval *zkey, zval *zvalue) {
    zend::String skey(zkey);
    auto item = new MapItem(zvalue);
    item->key = zend_string_init(skey.val(), skey.len(), 1);
    map->lock_.lock();
    zend_hash_update_ptr(&map->ht, item->key, item);
    map->lock_.unlock();
}

static void thread_map_count(Map *map, zval *return_value) {
    map->lock_.lock_rd();
    RETVAL_LONG(zend_array_count(&map->ht));
    map->lock_.unlock();
}

static void thread_map_intkey_offsetGet(Map *map, zval *zkey, zval *return_value) {
    zend_long index = zval_get_long(zkey);
    map->lock_.lock_rd();
    MapItem *tv = (MapItem *) zend_hash_index_find(&map->ht, index);
    if (tv) {
        tv->fetch(return_value);
    }
    map->lock_.unlock();
}

static void thread_map_intkey_offsetExists(Map *map, zval *zkey, zval *return_value) {
    zend_long index = zval_get_long(zkey);
    map->lock_.lock_rd();
    RETVAL_BOOL(zend_hash_index_find_ptr(&map->ht, index) != NULL);
    map->lock_.unlock();
}

static void thread_map_intkey_offsetUnset(Map *map, zval *zkey) {
    zend_long index = zval_get_long(zkey);
    map->lock_.lock();
    zend_hash_index_del(&map->ht, index);
    map->lock_.unlock();
}

static void thread_map_intkey_offsetSet(Map *map, zval *zkey, zval *zvalue) {
    zend_long index = zval_get_long(zkey);
    auto item = new MapItem(zvalue);
    map->lock_.lock();
    zend_hash_index_update_ptr(&map->ht, index, item);
    map->lock_.unlock();
}

static sw_inline ThreadArrayListObject *thread_arraylist_fetch_object(zend_object *obj) {
    return (ThreadArrayListObject *) ((char *) obj - swoole_thread_arraylist_handlers.offset);
}

static sw_inline zend_long thread_arraylist_get_resource_id(zend_object *obj) {
    zval rv, *property = zend_read_property(swoole_thread_arraylist_ce, obj, ZEND_STRL("id"), 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static sw_inline zend_long thread_arraylist_get_resource_id(zval *zobject) {
    return thread_arraylist_get_resource_id(Z_OBJ_P(zobject));
}

static void thread_arraylist_free_object(zend_object *object) {
    zend_long resource_id = thread_arraylist_get_resource_id(object);
    ThreadArrayListObject *ao = thread_arraylist_fetch_object(object);
    if (ao->resource) {
        thread_lock.lock();
        if (ao->resource->del_ref() == 0) {
            thread_resources.erase(resource_id);
            delete ao->resource;
            ao->resource = nullptr;
        }
        thread_lock.unlock();
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_arraylist_create_object(zend_class_entry *ce) {
    ThreadArrayListObject *ao = (ThreadArrayListObject *) zend_object_alloc(sizeof(ThreadArrayListObject), ce);
    zend_object_std_init(&ao->std, ce);
    object_properties_init(&ao->std, ce);
    ao->std.handlers = &swoole_thread_arraylist_handlers;
    return &ao->std;
}

ThreadArrayListObject *thread_arraylist_fetch_object_check(zval *zobject) {
    ThreadArrayListObject *ao = thread_arraylist_fetch_object(Z_OBJ_P(zobject));
    if (!ao->resource) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return ao;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread, __construct);
static PHP_METHOD(swoole_thread, join);
static PHP_METHOD(swoole_thread, joinable);
static PHP_METHOD(swoole_thread, detach);
static PHP_METHOD(swoole_thread, exec);
static PHP_METHOD(swoole_thread, getArguments);
static PHP_METHOD(swoole_thread, getId);

static PHP_METHOD(swoole_thread_map, __construct);
static PHP_METHOD(swoole_thread_map, offsetGet);
static PHP_METHOD(swoole_thread_map, offsetExists);
static PHP_METHOD(swoole_thread_map, offsetSet);
static PHP_METHOD(swoole_thread_map, offsetUnset);
static PHP_METHOD(swoole_thread_map, count);
static PHP_METHOD(swoole_thread_map, __wakeup);

static PHP_METHOD(swoole_thread_arraylist, __construct);
static PHP_METHOD(swoole_thread_arraylist, offsetGet);
static PHP_METHOD(swoole_thread_arraylist, offsetExists);
static PHP_METHOD(swoole_thread_arraylist, offsetSet);
static PHP_METHOD(swoole_thread_arraylist, offsetUnset);
static PHP_METHOD(swoole_thread_arraylist, count);
static PHP_METHOD(swoole_thread_arraylist, __wakeup);

SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_methods[] = {
    PHP_ME(swoole_thread, __construct,  arginfo_class_Swoole_Thread___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, join,         arginfo_class_Swoole_Thread_join,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, joinable,     arginfo_class_Swoole_Thread_joinable,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, detach,       arginfo_class_Swoole_Thread_detach,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, exec,         arginfo_class_Swoole_Thread_exec,         ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getArguments, arginfo_class_Swoole_Thread_getArguments, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getId,        arginfo_class_Swoole_Thread_getId,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry swoole_thread_map_methods[] = {
    PHP_ME(swoole_thread_map, __construct,     arginfo_class_Swoole_Thread_Map___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetGet,       arginfo_class_Swoole_Thread_Map_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetExists,    arginfo_class_Swoole_Thread_Map_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetSet,       arginfo_class_Swoole_Thread_Map_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetUnset,     arginfo_class_Swoole_Thread_Map_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, count,           arginfo_class_Swoole_Thread_Map_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, __wakeup,        arginfo_class_Swoole_Thread_Map___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_thread_arraylist_methods[] = {
    PHP_ME(swoole_thread_arraylist, __construct,  arginfo_class_Swoole_Thread_ArrayList___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetGet,    arginfo_class_Swoole_Thread_ArrayList_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetExists, arginfo_class_Swoole_Thread_ArrayList_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetSet,    arginfo_class_Swoole_Thread_ArrayList_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetUnset,  arginfo_class_Swoole_Thread_ArrayList_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, count,        arginfo_class_Swoole_Thread_ArrayList_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, __wakeup,     arginfo_class_Swoole_Thread_ArrayList___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread, "Swoole\\Thread", nullptr, swoole_thread_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_thread);
    SW_SET_CLASS_CLONEABLE(swoole_thread, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread, php_swoole_thread_create_object, php_swoole_thread_free_object, ThreadObject, std);

    zend_declare_property_long(swoole_thread_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_class_constant_long(
        swoole_thread_ce, ZEND_STRL("HARDWARE_CONCURRENCY"), std::thread::hardware_concurrency());

    SW_INIT_CLASS_ENTRY(swoole_thread_map, "Swoole\\Thread\\Map", nullptr, swoole_thread_map_methods);
    SW_SET_CLASS_CLONEABLE(swoole_thread_map, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_map, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_map, thread_map_create_object, thread_map_free_object, ThreadMapObject, std);

    zend_class_implements(swoole_thread_map_ce, 2, zend_ce_arrayaccess, zend_ce_countable);

    zend_declare_class_constant_long(swoole_thread_map_ce, ZEND_STRL("KEY_INT"), Map::KEY_INT);
    zend_declare_class_constant_long(swoole_thread_map_ce, ZEND_STRL("KEY_STR"), Map::KEY_STR);

    zend_declare_property_long(swoole_thread_map_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY(swoole_thread_arraylist, "Swoole\\Thread\\ArrayList", nullptr, swoole_thread_arraylist_methods);
    SW_SET_CLASS_CLONEABLE(swoole_thread_arraylist, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_arraylist, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_arraylist,
                               thread_arraylist_create_object,
                               thread_arraylist_free_object,
                               ThreadArrayListObject,
                               std);

    zend_class_implements(swoole_thread_arraylist_ce, 2, zend_ce_arrayaccess, zend_ce_countable);
    zend_declare_property_long(swoole_thread_arraylist_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_thread, __construct) {}

static PHP_METHOD(swoole_thread, join) {
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!to || !to->thread || !to->thread->joinable()) {
        RETURN_FALSE;
    }
    php_swoole_thread_join(Z_OBJ_P(ZEND_THIS));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread, joinable) {
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (to == nullptr || !to->thread) {
        RETURN_FALSE;
    }
    RETURN_BOOL(to->thread->joinable());
}

static PHP_METHOD(swoole_thread, detach) {
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (to == nullptr || !to->thread) {
        RETURN_FALSE;
    }
    to->thread->detach();
    delete to->thread;
    to->thread = nullptr;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread, getArguments) {
    if (!ZVAL_IS_ARRAY(&thread_argv)) {
        array_init(&thread_argv);
    }
    RETURN_ZVAL(&thread_argv, 1, 0);
}

static PHP_METHOD(swoole_thread, getId) {
    RETURN_LONG(pthread_self());
}

std::string php_swoole_thread_serialize(zval *zdata) {
    php_serialize_data_t var_hash;
    smart_str serialized_data = {0};

    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&serialized_data, zdata, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);

    std::string result;
    if (!EG(exception)) {
        result = std::string(serialized_data.s->val, serialized_data.s->len);
    }
    smart_str_free(&serialized_data);
    return result;
}

bool php_swoole_thread_unserialize(const std::string &data, zval *zv) {
    php_unserialize_data_t var_hash;
    const char *p = data.c_str();
    size_t l = data.length();

    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    zend_bool unserialized = php_var_unserialize(zv, (const uchar **) &p, (const uchar *) (p + l), &var_hash);
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    if (!unserialized) {
        swoole_warning("unserialize() failed, Error at offset " ZEND_LONG_FMT " of %zd bytes",
                       (zend_long) ((char *) p - data.c_str()),
                       l);
    }
    return unserialized;
}

void php_swoole_thread_rshutdown() {
    zval_dtor(&thread_argv);
}

void php_swoole_thread_start(const std::string &file, const std::string &argv) {
    ts_resource(0);
#if defined(COMPILE_DL_SWOOLE)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    zend_file_handle file_handle{};

    if (php_request_startup() != SUCCESS) {
        EG(exit_status) = 1;
        goto _startup_error;
    }

    zend_stream_init_filename(&file_handle, file.c_str());
    file_handle.primary_script = 1;

    zend_first_try {
        if (argv.empty()) {
            array_init(&thread_argv);
        } else {
            php_swoole_thread_unserialize(argv, &thread_argv);
        }
        php_execute_script(&file_handle);
    }
    zend_end_try();

    zend_destroy_file_handle(&file_handle);
    php_request_shutdown(NULL);
    file_handle.filename = NULL;

_startup_error:
    ts_free_thread();
}

static PHP_METHOD(swoole_thread, exec) {
    char *script_file;
    size_t l_script_file;
    zval *args;
    int argc;

    ZEND_PARSE_PARAMETERS_START(1, -1)
    Z_PARAM_STRING(script_file, l_script_file)
    Z_PARAM_VARIADIC('+', args, argc)
    ZEND_PARSE_PARAMETERS_END();

    if (l_script_file < 1) {
        php_swoole_fatal_error(E_WARNING, "exec file name is empty");
        RETURN_FALSE;
    }

    object_init_ex(return_value, swoole_thread_ce);
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(return_value));
    std::string file(script_file, l_script_file);

    zval zargv;
    array_init(&zargv);
    for (int i = 0; i < argc; i++) {
        zend::array_add(&zargv, &args[i]);
    }
    std::string argv = php_swoole_thread_serialize(&zargv);
    zval_dtor(&zargv);

    to->thread = new std::thread([file, argv]() { php_swoole_thread_start(file, argv); });
    zend_update_property_long(
        swoole_thread_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("id"), to->thread->native_handle());
}

static void thread_map_value_dtor(zval *pDest) {
    MapItem *item = (MapItem *) Z_PTR_P(pDest);
    delete item;
}

static PHP_METHOD(swoole_thread_map, __construct) {
    zend_long key_type;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(key_type)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object(Z_OBJ_P(ZEND_THIS));
    mo->map = new Map(key_type);

    if (key_type == Map::KEY_INT) {
        mo->handlers = &map_intkey_handlers;
    } else {
        mo->handlers = &map_strkey_handlers;
    }

    thread_lock.lock();
    zend_long resource_id = ++thread_resource_id;
    thread_resources[resource_id] = mo->map;
    thread_lock.unlock();

    zend_update_property_long(swoole_thread_map_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
}

static PHP_METHOD(swoole_thread_map, offsetGet) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->handlers->offsetGet(mo->map, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetExists) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->handlers->offsetExists(mo->map, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->handlers->offsetSet(mo->map, zkey, zvalue);
}

static PHP_METHOD(swoole_thread_map, offsetUnset) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->handlers->offsetUnset(mo->map, zkey);
}

static PHP_METHOD(swoole_thread_map, count) {
    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->handlers->count(mo->map, return_value);
}

static PHP_METHOD(swoole_thread_map, __wakeup) {
    auto mo = thread_map_fetch_object(Z_OBJ_P(ZEND_THIS));
    bool success = false;
    zend_long resource_id = thread_map_get_resource_id(ZEND_THIS);

    thread_lock.lock();
    auto iter = thread_resources.find(resource_id);
    if (iter != thread_resources.end()) {
        Map *map = (Map *) iter->second;
        map->add_ref();
        if (map->type_ == Map::KEY_INT) {
            mo->handlers = &map_intkey_handlers;
        } else {
            mo->handlers = &map_strkey_handlers;
        }
        mo->map = map;
        success = true;
    }
    thread_lock.unlock();

    if (!success) {
        zend_throw_exception(swoole_exception_ce, "resource not found", -2);
    }
}

static PHP_METHOD(swoole_thread_arraylist, __construct) {
    ZEND_PARSE_PARAMETERS_NONE();

    auto ao = thread_arraylist_fetch_object(Z_OBJ_P(ZEND_THIS));
    ao->resource = new ArrayList();

    thread_lock.lock();
    zend_long resource_id = ++thread_resource_id;
    thread_resources[resource_id] = ao->resource;
    thread_lock.unlock();

    zend_update_property_long(swoole_thread_arraylist_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
}

static PHP_METHOD(swoole_thread_arraylist, offsetGet) {
    zend_long index;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(index)
    ZEND_PARSE_PARAMETERS_END();

    bool out_of_range = true;
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->resource->lock_.lock_rd();
    if (ao->resource->exists(index)) {
        out_of_range = false;
        ao->resource->list_.at(index)->fetch(return_value);
    }
    ao->resource->lock_.unlock();

    if (out_of_range) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetExists) {
    zend_long index;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(index)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->resource->lock_.lock_rd();
    RETVAL_BOOL(ao->resource->exists(index));
    ao->resource->lock_.unlock();
}

static PHP_METHOD(swoole_thread_arraylist, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ArrayList *array = ao->resource;

    array->lock_.lock();
    if (ZVAL_IS_NULL(zkey) || (ZVAL_IS_LONG(zkey) && Z_LVAL_P(zkey) == (zend_long) array->list_.size())) {
        array->list_.emplace_back(new MapItem(zvalue));
    } else {
        zend_long index = zval_get_long(zkey);
        array->list_.at(index)->assign(zvalue);
    }
    array->lock_.unlock();
}

static PHP_METHOD(swoole_thread_arraylist, offsetUnset) {
    zend_throw_exception(swoole_exception_ce, "unsupported", -3);
}

static PHP_METHOD(swoole_thread_arraylist, count) {
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->resource->lock_.lock_rd();
    RETVAL_LONG(ao->resource->list_.size());
    ao->resource->lock_.unlock();
}

static PHP_METHOD(swoole_thread_arraylist, __wakeup) {
    auto mo = thread_arraylist_fetch_object(Z_OBJ_P(ZEND_THIS));
    bool success = false;
    zend_long resource_id = thread_arraylist_get_resource_id(ZEND_THIS);

    thread_lock.lock();
    auto iter = thread_resources.find(resource_id);
    if (iter != thread_resources.end()) {
        ArrayList *array = (ArrayList *) iter->second;
        array->add_ref();
        mo->resource = array;
        success = true;
    }
    thread_lock.unlock();

    if (!success) {
        zend_throw_exception(swoole_exception_ce, "resource not found", -2);
    }
}

#endif
