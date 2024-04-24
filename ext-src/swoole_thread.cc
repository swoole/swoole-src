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

zend_class_entry *swoole_thread_ce;
static zend_object_handlers swoole_thread_handlers;

static struct {
    char *path_translated;
    zend_string *argv_serialized;
    int argc;
} request_info;

TSRMLS_CACHE_DEFINE();

typedef std::thread Thread;

struct ThreadObject {
    Thread *thread;
    zend_object std;
};

static void php_swoole_thread_join(zend_object *object);

static thread_local zval thread_argv;
static zend_long thread_resource_id = 0;
static std::unordered_map<ThreadResourceId, ThreadResource *> thread_resources;

ThreadResourceId php_swoole_thread_resource_insert(ThreadResource *res) {
    std::unique_lock<std::mutex> _lock(sw_thread_lock);
    zend_long resource_id = ++thread_resource_id;
    thread_resources[resource_id] = res;
    return resource_id;
}

ThreadResource *php_swoole_thread_resource_fetch(ThreadResourceId resource_id) {
    ThreadResource *res = nullptr;
    std::unique_lock<std::mutex> _lock(sw_thread_lock);
    auto iter = thread_resources.find(resource_id);
    if (iter != thread_resources.end()) {
        res = iter->second;
        res->add_ref();
    }
    return res;
}

bool php_swoole_thread_resource_free(ThreadResourceId resource_id, ThreadResource *res) {
    std::unique_lock<std::mutex> _lock(sw_thread_lock);
    if (res->del_ref() == 0) {
        thread_resources.erase(resource_id);
        return true;
    } else {
        return false;
    }
}

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

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread, __construct);
static PHP_METHOD(swoole_thread, join);
static PHP_METHOD(swoole_thread, joinable);
static PHP_METHOD(swoole_thread, detach);
static PHP_METHOD(swoole_thread, exec);
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
    PHP_ME(swoole_thread, exec,         arginfo_class_Swoole_Thread_exec,         ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getArguments, arginfo_class_Swoole_Thread_getArguments, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getId,        arginfo_class_Swoole_Thread_getId,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getTsrmInfo,  arginfo_class_Swoole_Thread_getTsrmInfo,  ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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

    zend_declare_property_long(swoole_thread_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
    zend_declare_class_constant_long(
        swoole_thread_ce, ZEND_STRL("HARDWARE_CONCURRENCY"), std::thread::hardware_concurrency());
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

zval *php_swoole_thread_get_arguments() {
    if (!ZVAL_IS_ARRAY(&thread_argv)) {
        array_init(&thread_argv);
    }
    return &thread_argv;
}

static PHP_METHOD(swoole_thread, getArguments) {
    RETURN_ZVAL(php_swoole_thread_get_arguments(), 1, 0);
}

static PHP_METHOD(swoole_thread, getId) {
    RETURN_LONG(pthread_self());
}

zend_string *php_swoole_thread_serialize(zval *zdata) {
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

bool php_swoole_thread_unserialize(zend_string *data, zval *zv) {
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
        request_info.argv_serialized = php_swoole_thread_serialize(global_argv);
        request_info.argc = SG(request_info).argc;
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

void php_swoole_thread_start(zend_string *file, zend_string *argv_serialized) {
    ts_resource(0);
    TSRMLS_CACHE_UPDATE();
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
        if (argv_serialized == nullptr || ZSTR_LEN(argv_serialized) == 0) {
            array_init(&thread_argv);
        } else {
            php_swoole_thread_unserialize(argv_serialized, &thread_argv);
        }
        if (request_info.argv_serialized) {
            php_swoole_thread_unserialize(request_info.argv_serialized, &global_argv);
            ZVAL_LONG(&global_argc, request_info.argc);
            zend_hash_update(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_ARGV), &global_argv);
            zend_hash_update(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_ARGC), &global_argc);
        }
        php_execute_script(&file_handle);
    }
    zend_end_try();

    zend_destroy_file_handle(&file_handle);
    php_request_shutdown(NULL);
    file_handle.filename = NULL;

_startup_error:
    zend_string_release(file);
    zend_string_release(argv_serialized);
    ts_free_thread();
    swoole_thread_clean();
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
    zend_string *file = zend_string_init(script_file, l_script_file, 1);

    zval zargv;
    array_init(&zargv);
    for (int i = 0; i < argc; i++) {
        zend::array_add(&zargv, &args[i]);
    }
    zend_string *argv = php_swoole_thread_serialize(&zargv);
    zval_dtor(&zargv);

    if (!argv) {
        zend_string_release(file);
        return;
    }

    to->thread = new std::thread([file, argv]() { php_swoole_thread_start(file, argv); });
    zend_update_property_long(
        swoole_thread_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("id"), to->thread->native_handle());
}

static PHP_METHOD(swoole_thread, getTsrmInfo) {
    array_init(return_value);
    add_assoc_bool(return_value, "is_main_thread", tsrm_is_main_thread());
    add_assoc_bool(return_value, "is_shutdown", tsrm_is_shutdown());
    add_assoc_string(return_value, "api_name", tsrm_api_name());
}

#endif
