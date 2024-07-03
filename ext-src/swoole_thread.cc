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
#include "php_swoole_thread.h"

#ifdef SW_THREAD

#include <sys/ipc.h>
#include <sys/resource.h>

#include <thread>
#include <unordered_map>

#include "swoole_lock.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_arginfo.h"
END_EXTERN_C()

static zend_object_handlers swoole_thread_handlers;
static zend_object_handlers swoole_thread_error_handlers;

static struct {
    char *path_translated;
    zend_string *argv_serialized;
    int argc;
} request_info;

TSRMLS_CACHE_EXTERN();

typedef std::thread Thread;

struct ThreadObject {
    Thread *thread;
    zend_object std;
};

static void php_swoole_thread_join(zend_object *object);
static void php_swoole_thread_register_stdio_file_handles(bool no_close);

static thread_local zval thread_argv;
static thread_local JMP_BUF *thread_bailout = nullptr;

static sw_inline ThreadObject *thread_fetch_object(zend_object *obj) {
    return (ThreadObject *) ((char *) obj - swoole_thread_handlers.offset);
}

static void thread_free_object(zend_object *object) {
    php_swoole_thread_join(object);
    zend_object_std_dtor(object);
}

static zend_object *thread_create_object(zend_class_entry *ce) {
    ThreadObject *to = (ThreadObject *) zend_object_alloc(sizeof(ThreadObject), ce);
    zend_object_std_init(&to->std, ce);
    object_properties_init(&to->std, ce);
    to->std.handlers = &swoole_thread_handlers;
    return &to->std;
}

static void php_swoole_thread_join(zend_object *object) {
    ThreadObject *to = thread_fetch_object(object);
    if (to->thread && to->thread->joinable()) {
        to->thread->join();
        delete to->thread;
        to->thread = nullptr;
    }
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread, __construct);
static PHP_METHOD(swoole_thread, join);
static PHP_METHOD(swoole_thread, joinable);
static PHP_METHOD(swoole_thread, detach);
static PHP_METHOD(swoole_thread, getArguments);
static PHP_METHOD(swoole_thread, getId);
static PHP_METHOD(swoole_thread, getTsrmInfo);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_methods[] = {
    PHP_ME(swoole_thread, __construct,  arginfo_class_Swoole_Thread___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, join,         arginfo_class_Swoole_Thread_join,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, joinable,     arginfo_class_Swoole_Thread_joinable,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, detach,       arginfo_class_Swoole_Thread_detach,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, getArguments, arginfo_class_Swoole_Thread_getArguments, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getId,        arginfo_class_Swoole_Thread_getId,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getTsrmInfo,  arginfo_class_Swoole_Thread_getTsrmInfo,  ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread, "Swoole\\Thread", nullptr, swoole_thread_methods);
    swoole_thread_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread, thread_create_object, thread_free_object, ThreadObject, std);

    zend_declare_property_long(swoole_thread_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
    zend_declare_class_constant_long(
        swoole_thread_ce, ZEND_STRL("HARDWARE_CONCURRENCY"), std::thread::hardware_concurrency());

    SW_INIT_CLASS_ENTRY_DATA_OBJECT(swoole_thread_error, "Swoole\\Thread\\Error");
    zend_declare_property_long(swoole_thread_error_ce, ZEND_STRL("code"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
}

static PHP_METHOD(swoole_thread, __construct) {
    char *script_file;
    size_t l_script_file;
    zval *args;
    int argc;
    ZendArray *argv = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, -1)
    Z_PARAM_STRING(script_file, l_script_file)
    Z_PARAM_VARIADIC('+', args, argc)
    ZEND_PARSE_PARAMETERS_END();

    if (l_script_file < 1) {
        zend_throw_exception(swoole_exception_ce, "exec file name is empty", SW_ERROR_INVALID_PARAMS);
        return;
    }

    ThreadObject *to = thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_string *file = zend_string_init(script_file, l_script_file, 1);

    if (argc > 0) {
        argv = new ZendArray();
        for (int i = 0; i < argc; i++) {
            argv->append(&args[i]);
        }
    }

    try {
        to->thread = new std::thread([file, argv]() { php_swoole_thread_start(file, argv); });
    } catch (const std::exception &e) {
        zend_throw_exception(swoole_exception_ce, e.what(), SW_ERROR_SYSTEM_CALL_FAIL);
        return;
    }
    zend_update_property_long(
        swoole_thread_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), (zend_long) to->thread->native_handle());
}

static PHP_METHOD(swoole_thread, join) {
    ThreadObject *to = thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!to || !to->thread || !to->thread->joinable()) {
        RETURN_FALSE;
    }
    php_swoole_thread_join(Z_OBJ_P(ZEND_THIS));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread, joinable) {
    ThreadObject *to = thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (to == nullptr || !to->thread) {
        RETURN_FALSE;
    }
    RETURN_BOOL(to->thread->joinable());
}

static PHP_METHOD(swoole_thread, detach) {
    ThreadObject *to = thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (to == nullptr || !to->thread) {
        RETURN_FALSE;
    }
    to->thread->detach();
    delete to->thread;
    to->thread = nullptr;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread, getArguments) {
    RETURN_ZVAL(&thread_argv, 1, 0);
}

static PHP_METHOD(swoole_thread, getId) {
    RETURN_LONG((zend_long) pthread_self());
}

zend_string *php_swoole_serialize(zval *zdata) {
    php_serialize_data_t var_hash;
    smart_str serialized_data = {0};

    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&serialized_data, zdata, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);

    zend_string *result = nullptr;
    if (!EG(exception)) {
        result = zend_string_init(serialized_data.s->val, serialized_data.s->len, 1);
    }
    smart_str_free(&serialized_data);
    return result;
}

bool php_swoole_unserialize(zend_string *data, zval *zv) {
    php_unserialize_data_t var_hash;
    const char *p = ZSTR_VAL(data);
    size_t l = ZSTR_LEN(data);

    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    zend_bool unserialized = php_var_unserialize(zv, (const uchar **) &p, (const uchar *) (p + l), &var_hash);
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    if (!unserialized) {
        swoole_warning("unserialize() failed, Error at offset " ZEND_LONG_FMT " of %zd bytes",
                       (zend_long) ((char *) p - ZSTR_VAL(data)),
                       l);
    }
    return unserialized;
}

void php_swoole_thread_rinit() {
    if (tsrm_is_main_thread()) {
        if (SG(request_info).path_translated) {
            request_info.path_translated = strdup(SG(request_info).path_translated);
        }
        // Return reference
        zval *global_argv = zend_hash_find_ind(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_ARGV));
        if (global_argv) {
            request_info.argv_serialized = php_swoole_serialize(global_argv);
            request_info.argc = SG(request_info).argc;
        }
    }
}

void php_swoole_thread_rshutdown() {
    zval_dtor(&thread_argv);
    if (tsrm_is_main_thread()) {
        if (request_info.path_translated) {
            free((void *) request_info.path_translated);
            request_info.path_translated = nullptr;
        }
        if (request_info.argv_serialized) {
            zend_string_release(request_info.argv_serialized);
            request_info.argv_serialized = nullptr;
        }
    }
}

static void php_swoole_thread_register_stdio_file_handles(bool no_close) {
    php_stream *s_in, *s_out, *s_err;
    php_stream_context *sc_in = NULL, *sc_out = NULL, *sc_err = NULL;
    zend_constant ic, oc, ec;

    s_in = php_stream_open_wrapper_ex("php://stdin", "rb", 0, NULL, sc_in);
    s_out = php_stream_open_wrapper_ex("php://stdout", "wb", 0, NULL, sc_out);
    s_err = php_stream_open_wrapper_ex("php://stderr", "wb", 0, NULL, sc_err);

    if (s_in == NULL || s_out == NULL || s_err == NULL) {
        if (s_in) php_stream_close(s_in);
        if (s_out) php_stream_close(s_out);
        if (s_err) php_stream_close(s_err);
        return;
    }

    if (no_close) {
        s_in->flags |= PHP_STREAM_FLAG_NO_CLOSE;
        s_out->flags |= PHP_STREAM_FLAG_NO_CLOSE;
        s_err->flags |= PHP_STREAM_FLAG_NO_CLOSE;
    }

    php_stream_to_zval(s_in, &ic.value);
    php_stream_to_zval(s_out, &oc.value);
    php_stream_to_zval(s_err, &ec.value);

    ZEND_CONSTANT_SET_FLAGS(&ic, CONST_CS, 0);
    ic.name = zend_string_init_interned("STDIN", sizeof("STDIN") - 1, 0);
    zend_register_constant(&ic);

    ZEND_CONSTANT_SET_FLAGS(&oc, CONST_CS, 0);
    oc.name = zend_string_init_interned("STDOUT", sizeof("STDOUT") - 1, 0);
    zend_register_constant(&oc);

    ZEND_CONSTANT_SET_FLAGS(&ec, CONST_CS, 0);
    ec.name = zend_string_init_interned("STDERR", sizeof("STDERR") - 1, 0);
    zend_register_constant(&ec);
}

void php_swoole_thread_start(zend_string *file, ZendArray *argv) {
    ts_resource(0);
#if defined(COMPILE_DL_SWOOLE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    zend_file_handle file_handle{};
    zval global_argc, global_argv;

    PG(expose_php) = 0;
    PG(auto_globals_jit) = 1;
#if PHP_VERSION_ID >= 80100
    PG(enable_dl) = false;
#else
    PG(enable_dl) = 0;
#endif

    swoole_thread_init();

    if (php_request_startup() != SUCCESS) {
        EG(exit_status) = 1;
        goto _startup_error;
    }

    PG(during_request_startup) = 0;
    SG(sapi_started) = 0;
    SG(headers_sent) = 1;
    SG(request_info).no_headers = 1;
    SG(request_info).path_translated = request_info.path_translated;
    SG(request_info).argc = request_info.argc;

    zend_stream_init_filename(&file_handle, ZSTR_VAL(file));
    file_handle.primary_script = 1;

    zend_first_try {
        thread_bailout = EG(bailout);
        if (request_info.argv_serialized) {
            php_swoole_unserialize(request_info.argv_serialized, &global_argv);
            ZVAL_LONG(&global_argc, request_info.argc);
            zend_hash_update(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_ARGV), &global_argv);
            zend_hash_update(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_ARGC), &global_argc);
        }
        if (argv) {
            argv->toArray(&thread_argv);
            argv->del_ref();
        }
        php_swoole_thread_register_stdio_file_handles(true);
        php_execute_script(&file_handle);
    }
    zend_end_try();

    zend_destroy_file_handle(&file_handle);

    php_request_shutdown(NULL);
    file_handle.filename = NULL;

_startup_error:
    zend_string_release(file);
    ts_free_thread();
    swoole_thread_clean();
}

void php_swoole_thread_bailout(void) {
    if (thread_bailout) {
        EG(bailout) = thread_bailout;
        zend_bailout();
    }
}

int php_swoole_thread_stream_cast(zval *zstream) {
    php_stream *stream;
    int sockfd;
    int cast_flags = PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL;
    if ((php_stream_from_zval_no_verify(stream, zstream))) {
        if (php_stream_cast(stream, cast_flags, (void **) &sockfd, 1) == SUCCESS && sockfd >= 0) {
            return dup(sockfd);
        }
    }
    return -1;
}

int php_swoole_thread_co_socket_cast(zval *zvalue, swSocketType *type) {
    swoole::coroutine::Socket *socket = php_swoole_get_socket(zvalue);
    if (!socket) {
        return -1;
    }
    int sockfd = socket->get_fd();
    if (sockfd < 0) {
        return -1;
    }
    int newfd = dup(sockfd);
    if (newfd < 0) {
        return -1;
    }
    *type = socket->get_type();
    return newfd;
}

void php_swoole_thread_stream_create(zval *return_value, zend_long sockfd) {
    std::string path = "php://fd/" + std::to_string(sockfd);
    // The file descriptor will be duplicated once here
    php_stream *stream = php_stream_open_wrapper_ex(path.c_str(), "", 0, NULL, NULL);
    if (stream) {
        php_stream_to_zval(stream, return_value);
    } else {
        object_init_ex(return_value, swoole_thread_error_ce);
        zend::object_set(return_value, ZEND_STRL("code"), errno);
    }
}

void php_swoole_thread_co_socket_create(zval *return_value, zend_long sockfd, swSocketType type) {
    int newfd = dup(sockfd);
    if (newfd < 0) {
        object_init_ex(return_value, swoole_thread_error_ce);
        zend::object_set(return_value, ZEND_STRL("code"), errno);
        return;
    }
    zend_object *sockobj = php_swoole_create_socket_from_fd(newfd, type);
    if (sockobj) {
        ZVAL_OBJ(return_value, sockobj);
    } else {
        // never here
        abort();
    }
}

static PHP_METHOD(swoole_thread, getTsrmInfo) {
    array_init(return_value);
    add_assoc_bool(return_value, "is_main_thread", tsrm_is_main_thread());
    add_assoc_bool(return_value, "is_shutdown", tsrm_is_shutdown());
    add_assoc_string(return_value, "api_name", tsrm_api_name());
}

#define CAST_OBJ_TO_RESOURCE(_name, _type)                                                                             \
    else if (instanceof_function(Z_OBJCE_P(zvalue), swoole_thread_##_name##_ce)) {                                     \
        value.resource = php_swoole_thread_##_name##_cast(zvalue);                                                     \
        value.resource->add_ref();                                                                                     \
        type = _type;                                                                                                  \
        break;                                                                                                         \
    }

void ArrayItem::store(zval *zvalue) {
    type = Z_TYPE_P(zvalue);
    switch (type) {
    case IS_LONG:
        value.lval = zval_get_long(zvalue);
        break;
    case IS_DOUBLE:
        value.dval = zval_get_double(zvalue);
        break;
    case IS_STRING: {
        value.str = zend_string_init(Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue), 1);
        break;
    }
    case IS_TRUE:
    case IS_FALSE:
    case IS_NULL:
        break;
    case IS_RESOURCE: {
        value.socket.fd = php_swoole_thread_stream_cast(zvalue);
        type = IS_STREAM_SOCKET;
        if (value.socket.fd == -1) {
            zend_throw_exception(swoole_exception_ce, "failed to convert to socket fd", errno);
        }
        break;
    }
    case IS_ARRAY: {
        type = zend_array_is_list(Z_ARRVAL_P(zvalue)) ? IS_ARRAYLIST : IS_MAP;
        value.resource = ZendArray::from(Z_ARRVAL_P(zvalue));
        break;
    }
    case IS_OBJECT: {
        if (instanceof_function(Z_OBJCE_P(zvalue), swoole_socket_coro_ce)) {
            value.socket.fd = php_swoole_thread_co_socket_cast(zvalue, &value.socket.type);
            type = IS_CO_SOCKET;
            if (value.socket.fd == -1) {
                zend_throw_exception(swoole_exception_ce, "failed to convert to socket fd", errno);
            }
            break;
        }
        CAST_OBJ_TO_RESOURCE(arraylist, IS_ARRAYLIST)
        CAST_OBJ_TO_RESOURCE(map, IS_MAP)
        CAST_OBJ_TO_RESOURCE(queue, IS_QUEUE)
        CAST_OBJ_TO_RESOURCE(lock, IS_LOCK)
        CAST_OBJ_TO_RESOURCE(atomic, IS_ATOMIC)
        CAST_OBJ_TO_RESOURCE(atomic_long, IS_ATOMIC_LONG)
        CAST_OBJ_TO_RESOURCE(barrier, IS_BARRIER)
    }
    /* no break */
    default: {
        auto _serialized_object = php_swoole_serialize(zvalue);
        if (!_serialized_object) {
            type = IS_UNDEF;
            break;
        } else {
            type = IS_SERIALIZED_OBJECT;
            value.serialized_object = _serialized_object;
        }
        break;
    }
    }
}

void ArrayItem::fetch(zval *return_value) {
    switch (type) {
    case IS_LONG:
        RETVAL_LONG(value.lval);
        break;
    case IS_DOUBLE:
        RETVAL_DOUBLE(value.dval);
        break;
    case IS_TRUE:
        RETVAL_TRUE;
        break;
    case IS_FALSE:
        RETVAL_FALSE;
        break;
    case IS_STRING:
        RETVAL_NEW_STR(zend_string_init(ZSTR_VAL(value.str), ZSTR_LEN(value.str), 0));
        break;
    case IS_ARRAYLIST:
        value.resource->add_ref();
        php_swoole_thread_arraylist_create(return_value, value.resource);
        break;
    case IS_QUEUE:
        value.resource->add_ref();
        php_swoole_thread_queue_create(return_value, value.resource);
        break;
    case IS_LOCK:
        value.resource->add_ref();
        php_swoole_thread_lock_create(return_value, value.resource);
        break;
    case IS_MAP:
        value.resource->add_ref();
        php_swoole_thread_map_create(return_value, value.resource);
        break;
    case IS_BARRIER:
        value.resource->add_ref();
        php_swoole_thread_barrier_create(return_value, value.resource);
        break;
    case IS_ATOMIC:
        value.resource->add_ref();
        php_swoole_thread_atomic_create(return_value, value.resource);
        break;
    case IS_ATOMIC_LONG:
        value.resource->add_ref();
        php_swoole_thread_atomic_long_create(return_value, value.resource);
        break;
    case IS_STREAM_SOCKET:
        php_swoole_thread_stream_create(return_value, value.socket.fd);
        break;
    case IS_CO_SOCKET:
        php_swoole_thread_co_socket_create(return_value, value.socket.fd, value.socket.type);
        break;
    case IS_SERIALIZED_OBJECT:
        php_swoole_unserialize(value.serialized_object, return_value);
        break;
    default:
        break;
    }
}

void ArrayItem::release() {
    if (type == IS_STRING) {
        zend_string_release(value.str);
        value.str = nullptr;
    } else if (type == IS_STREAM_SOCKET || type == IS_CO_SOCKET) {
        close(value.socket.fd);
        value.socket.fd = -1;
    } else if (type == IS_SERIALIZED_OBJECT) {
        zend_string_release(value.serialized_object);
        value.serialized_object = nullptr;
    } else if (type >= IS_ARRAYLIST && type <= IS_ATOMIC_LONG) {
        value.resource->del_ref();
        value.resource = nullptr;
    }
}

#define INIT_DECR_VALUE(v)                                                                                             \
    zval rvalue = *v;                                                                                                  \
    if (Z_TYPE_P(v) == IS_DOUBLE) {                                                                                    \
        rvalue.value.dval = -rvalue.value.dval;                                                                        \
    } else {                                                                                                           \
        ZVAL_LONG(&rvalue, -zval_get_long(v));                                                                         \
    }

void ZendArray::incr_update(ArrayItem *item, zval *zvalue, zval *return_value) {
    if (item->type == IS_DOUBLE) {
        item->value.dval += zval_get_double(zvalue);
        RETVAL_DOUBLE(item->value.dval);
    } else {
        item->value.lval += zval_get_long(zvalue);
        RETVAL_LONG(item->value.lval);
    }
}

ArrayItem *ZendArray::incr_create(zval *zvalue, zval *return_value) {
    zval rvalue = *zvalue;
    if (Z_TYPE_P(zvalue) == IS_DOUBLE) {
        RETVAL_DOUBLE(rvalue.value.dval);
    } else {
        ZVAL_LONG(&rvalue, zval_get_long(zvalue));
        RETVAL_LONG(rvalue.value.lval);
    }
    return new ArrayItem(&rvalue);
}

void ZendArray::strkey_incr(zval *zkey, zval *zvalue, zval *return_value) {
    zend::String skey(zkey);
    ArrayItem *item;

    lock_.lock();
    item = (ArrayItem *) zend_hash_find_ptr(&ht, skey.get());
    if (item) {
        incr_update(item, zvalue, return_value);
    } else {
        item = incr_create(zvalue, return_value);
        item->setKey(skey);
        zend_hash_update_ptr(&ht, item->key, item);
    }
    lock_.unlock();
}

void ZendArray::intkey_incr(zval *zkey, zval *zvalue, zval *return_value) {
    ArrayItem *item;
    zend_long index = zval_get_long(zkey);
    lock_.lock();
    item = (ArrayItem *) (ArrayItem *) zend_hash_index_find_ptr(&ht, index);
    if (item) {
        incr_update(item, zvalue, return_value);
    } else {
        item = incr_create(zvalue, return_value);
        item = new ArrayItem(zvalue);
        zend_hash_index_update_ptr(&ht, index, item);
    }
    lock_.unlock();
}

void ZendArray::strkey_decr(zval *zkey, zval *zvalue, zval *return_value) {
    INIT_DECR_VALUE(zvalue);
    strkey_incr(zkey, &rvalue, return_value);
}

void ZendArray::intkey_decr(zval *zkey, zval *zvalue, zval *return_value) {
    INIT_DECR_VALUE(zvalue);
    intkey_incr(zkey, &rvalue, return_value);
}

void ZendArray::strkey_add(zval *zkey, zval *zvalue, zval *return_value) {
    zend::String skey(zkey);
    lock_.lock();
    if (strkey_exists(skey)) {
        RETVAL_FALSE;
    } else {
        add(skey, zvalue);
        RETVAL_TRUE;
    }
    lock_.unlock();
}

void ZendArray::intkey_add(zval *zkey, zval *zvalue, zval *return_value) {
    zend_long index = zval_get_long(zkey);
    lock_.lock();
    if (intkey_exists(index)) {
        RETVAL_FALSE;
    } else {
        add(index, zvalue);
        RETVAL_TRUE;
    }
    lock_.unlock();
}

void ZendArray::strkey_update(zval *zkey, zval *zvalue, zval *return_value) {
    zend::String skey(zkey);
    lock_.lock();
    if (!strkey_exists(skey)) {
        RETVAL_FALSE;
    } else {
        auto item = new ArrayItem(zvalue);
        item->setKey(skey);
        zend_hash_update_ptr(&ht, item->key, item);
        RETVAL_TRUE;
    }
    lock_.unlock();
}

void ZendArray::intkey_update(zval *zkey, zval *zvalue, zval *return_value) {
    zend_long index = zval_get_long(zkey);
    lock_.lock();
    if (!intkey_exists(index)) {
        RETVAL_FALSE;
    } else {
        auto item = new ArrayItem(zvalue);
        zend_hash_index_update_ptr(&ht, index, item);
        RETVAL_TRUE;
    }
    lock_.unlock();
}

bool ZendArray::index_offsetSet(zval *zkey, zval *zvalue) {
    zend_long index = ZVAL_IS_NULL(zkey) ? -1 : zval_get_long(zkey);
    auto item = new ArrayItem(zvalue);
    bool success = true;
    lock_.lock();
    if (index > zend_hash_num_elements(&ht)) {
        success = false;
        delete item;
    } else if (index == -1 || index == zend_hash_num_elements(&ht)) {
        zend_hash_next_index_insert_ptr(&ht, item);
    } else {
        zend_hash_index_update_ptr(&ht, index, item);
    }
    lock_.unlock();
    return success;
}

void ZendArray::append(zval *zvalue) {
    zend_hash_next_index_insert_ptr(&ht, new ArrayItem(zvalue));
}

bool ZendArray::index_incr(zval *zkey, zval *zvalue, zval *return_value) {
    zend_long index = ZVAL_IS_NULL(zkey) ? -1 : zval_get_long(zkey);

    bool success = true;
    lock_.lock();
    if (index > zend_hash_num_elements(&ht)) {
        success = false;
    } else if (index == -1 || index == zend_hash_num_elements(&ht)) {
        auto item = incr_create(zvalue, return_value);
        zend_hash_next_index_insert_ptr(&ht, item);
    } else {
        auto item = (ArrayItem *) zend_hash_index_find_ptr(&ht, index);
        incr_update(item, zvalue, return_value);
    }
    lock_.unlock();
    return success;
}

bool ZendArray::index_decr(zval *zkey, zval *zvalue, zval *return_value) {
    INIT_DECR_VALUE(zvalue);
    return index_incr(zkey, &rvalue, return_value);
}

void ZendArray::keys(zval *return_value) {
    lock_.lock_rd();
    zend_ulong elem_count = zend_hash_num_elements(&ht);
    array_init_size(return_value, elem_count);
    zend_hash_real_init_packed(Z_ARRVAL_P(return_value));
    zend_ulong num_idx;
    zend_string *str_idx;
    zval *entry;
    ZEND_HASH_FILL_PACKED(Z_ARRVAL_P(return_value)) {
        if (HT_IS_PACKED(&ht) && HT_IS_WITHOUT_HOLES(&ht)) {
            /* Optimistic case: range(0..n-1) for vector-like packed array */
            zend_ulong lval = 0;

            for (; lval < elem_count; ++lval) {
                ZEND_HASH_FILL_SET_LONG(lval);
                ZEND_HASH_FILL_NEXT();
            }
        } else {
            /* Go through input array and add keys to the return array */
            ZEND_HASH_FOREACH_KEY_VAL(&ht, num_idx, str_idx, entry) {
                if (str_idx) {
                    ZEND_HASH_FILL_SET_STR(zend_string_init(str_idx->val, str_idx->len, 0));
                } else {
                    ZEND_HASH_FILL_SET_LONG(num_idx);
                }
                ZEND_HASH_FILL_NEXT();
            }
            ZEND_HASH_FOREACH_END();
        }
        (void) entry;
    }
    ZEND_HASH_FILL_END();
    lock_.unlock();
}

void ZendArray::toArray(zval *return_value) {
    lock_.lock_rd();
    zend_ulong elem_count = zend_hash_num_elements(&ht);
    array_init_size(return_value, elem_count);
    zend_string *key;
    zend_ulong index;
    void *tmp;
    ZEND_HASH_FOREACH_KEY_PTR(&ht, index, key, tmp) {
        zval value;
        ArrayItem *item = (ArrayItem *) tmp;
        item->fetch(&value);
        if (key) {
            zend_hash_add(Z_ARR_P(return_value), key, &value);
        } else {
            zend_hash_index_add(Z_ARR_P(return_value), index, &value);
        }
    }
    ZEND_HASH_FOREACH_END();
    lock_.unlock();
}

ZendArray *ZendArray::from(zend_array *src) {
    zend_string *key;
    zend_ulong index;
    zval *tmp;
    ZendArray *result = new ZendArray();
    ZEND_HASH_FOREACH_KEY_VAL(src, index, key, tmp) {
        ZVAL_DEREF(tmp);
        if (key) {
            result->add(key, tmp);
        } else {
            result->add(index, tmp);
        }
    }
    ZEND_HASH_FOREACH_END();
    return result;
}

#endif
