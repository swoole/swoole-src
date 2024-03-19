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

#include <sys/ipc.h>
#include <sys/resource.h>

#include <thread>

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_arginfo.h"
END_EXTERN_C()

using namespace swoole;

zend_class_entry *swoole_thread_ce;
static zend_object_handlers swoole_thread_handlers;
typedef std::thread Thread;
thread_local zval thread_argv;

struct ThreadObject {
    Thread *thread;
    zend_object std;
};

static sw_inline ThreadObject *php_swoole_thread_fetch_object(zend_object *obj) {
    return (ThreadObject *) ((char *) obj - swoole_thread_handlers.offset);
}

static void php_swoole_thread_join(zend_object *object) {
    ThreadObject *to = php_swoole_thread_fetch_object(object);
    if (to->thread && to->thread->joinable()) {
        to->thread->join();
        delete to->thread;
        to->thread = nullptr;
    }
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

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread, __construct);
static PHP_METHOD(swoole_thread, join);
static PHP_METHOD(swoole_thread, run);
static PHP_METHOD(swoole_thread, getArguments);
static PHP_METHOD(swoole_thread, getId);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_methods[] =
{
    PHP_ME(swoole_thread, __construct,  arginfo_class_Swoole_Thread___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, join,         arginfo_class_Swoole_Thread_join,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread, run,          arginfo_class_Swoole_Thread_run,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getArguments, arginfo_class_Swoole_Thread_getArguments, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_thread, getId,        arginfo_class_Swoole_Thread_getId,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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

    zend_declare_property_null(swoole_thread_ce, ZEND_STRL("id"), ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_thread, __construct) {}

static PHP_METHOD(swoole_thread, join) {
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (to == nullptr || !to->thread->joinable()) {
        RETURN_FALSE;
    }
    php_swoole_thread_join(Z_OBJ_P(ZEND_THIS));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread, getArguments) {
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

void php_swoole_thread_rshutdown() {}

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
    zval_dtor(&thread_argv);

    php_request_shutdown(NULL);
    file_handle.filename = NULL;

_startup_error:
    ts_free_thread();
}

static PHP_METHOD(swoole_thread, run) {
    char *execfile = nullptr;
    size_t execfile_len = 0;
    zval *args;
    int argc;

    ZEND_PARSE_PARAMETERS_START(1, -1)
    Z_PARAM_STRING(execfile, execfile_len)
    Z_PARAM_VARIADIC('+', args, argc)
    ZEND_PARSE_PARAMETERS_END();

    if (execfile_len < 1) {
        php_swoole_fatal_error(E_WARNING, "exec file name is empty");
        RETURN_FALSE;
    }

    object_init_ex(return_value, swoole_thread_ce);
    ThreadObject *to = php_swoole_thread_fetch_object(Z_OBJ_P(return_value));
    std::string file(execfile, execfile_len);

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
