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
#include "php_swoole_library.h"
#include "php_swoole_process.h"
#include "php_swoole_thread.h"
#include "swoole_iouring.h"

BEGIN_EXTERN_C()
#include "zend_exceptions.h"
#include "zend_extensions.h"

#include "ext/pcre/php_pcre.h"
#include "ext/json/php_json.h"

#include "stubs/php_swoole_arginfo.h"
#include "stubs/php_swoole_ex_arginfo.h"
END_EXTERN_C()

#include "swoole_mime_type.h"
#include "swoole_server.h"
#include "swoole_util.h"
#include "swoole_http2.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>

#ifdef SW_USE_CURL
#include <curl/curl.h>
#endif

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/if_dl.h>
#endif

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_HAVE_BROTLI
#include <brotli/encode.h>
#include <brotli/decode.h>
#endif

#ifdef SW_HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef SW_USE_CARES
#include <ares.h>
#endif

using swoole::Server;
using swoole::network::Socket;
#ifdef SW_USE_IOURING
using swoole::Iouring;
#endif

ZEND_DECLARE_MODULE_GLOBALS(swoole)

extern sapi_module_struct sapi_module;

static swoole::CallbackManager rshutdown_callbacks;

SW_EXTERN_C_BEGIN
static PHP_FUNCTION(swoole_version);
static PHP_FUNCTION(swoole_cpu_num);
static PHP_FUNCTION(swoole_strerror);
static PHP_FUNCTION(swoole_clear_error);
static PHP_FUNCTION(swoole_errno);
static PHP_FUNCTION(swoole_error_log);
static PHP_FUNCTION(swoole_error_log_ex);
static PHP_FUNCTION(swoole_ignore_error);
static PHP_FUNCTION(swoole_get_local_ip);
static PHP_FUNCTION(swoole_get_local_mac);
static PHP_FUNCTION(swoole_hashcode);
static PHP_FUNCTION(swoole_mime_type_add);
static PHP_FUNCTION(swoole_mime_type_set);
static PHP_FUNCTION(swoole_mime_type_delete);
static PHP_FUNCTION(swoole_mime_type_get);
static PHP_FUNCTION(swoole_mime_type_exists);
static PHP_FUNCTION(swoole_mime_type_list);
static PHP_FUNCTION(swoole_substr_unserialize);
static PHP_FUNCTION(swoole_substr_json_decode);
static PHP_FUNCTION(swoole_internal_call_user_shutdown_begin);
static PHP_FUNCTION(swoole_implicit_fn);
SW_EXTERN_C_END

// clang-format off
const zend_function_entry swoole_functions[] = {
    PHP_FE(swoole_version,    arginfo_swoole_version)
    PHP_FE(swoole_cpu_num,    arginfo_swoole_cpu_num)
    PHP_FE(swoole_last_error, arginfo_swoole_last_error)
    /*------swoole_async_io------*/
    PHP_FE(swoole_async_dns_lookup_coro, arginfo_swoole_async_dns_lookup_coro)
    PHP_FE(swoole_async_set,             arginfo_swoole_async_set)
    /*------swoole_coroutine------*/
    PHP_FE(swoole_coroutine_create,      arginfo_swoole_coroutine_create)
    PHP_FE(swoole_coroutine_defer,       arginfo_swoole_coroutine_defer)
    PHP_FE(swoole_coroutine_socketpair,  arginfo_swoole_coroutine_socketpair)
    PHP_FE(swoole_test_kernel_coroutine, arginfo_swoole_test_kernel_coroutine)
    /*------other-----*/
    PHP_FE(swoole_client_select,      arginfo_swoole_client_select)
    PHP_FALIAS(swoole_select,         swoole_client_select, arginfo_swoole_client_select)
    PHP_FE(swoole_set_process_name,   arginfo_swoole_set_process_name)
    PHP_FE(swoole_get_local_ip,       arginfo_swoole_get_local_ip)
    PHP_FE(swoole_get_local_mac,      arginfo_swoole_get_local_mac)
    PHP_FE(swoole_strerror,           arginfo_swoole_strerror)
    PHP_FE(swoole_errno,              arginfo_swoole_errno)
    PHP_FE(swoole_clear_error,        arginfo_swoole_clear_error)
    PHP_FE(swoole_error_log,          arginfo_swoole_error_log)
    PHP_FE(swoole_error_log_ex,       arginfo_swoole_error_log_ex)
    PHP_FE(swoole_ignore_error,       arginfo_swoole_ignore_error)
    PHP_FE(swoole_hashcode,           arginfo_swoole_hashcode)
    PHP_FE(swoole_mime_type_add,      arginfo_swoole_mime_type_add)
    PHP_FE(swoole_mime_type_set,      arginfo_swoole_mime_type_set)
    PHP_FE(swoole_mime_type_delete,   arginfo_swoole_mime_type_delete)
    PHP_FE(swoole_mime_type_get,      arginfo_swoole_mime_type_get)
    PHP_FALIAS(swoole_get_mime_type,  swoole_mime_type_get, arginfo_swoole_mime_type_get)
    PHP_FE(swoole_mime_type_exists,   arginfo_swoole_mime_type_exists)
    PHP_FE(swoole_mime_type_list,     arginfo_swoole_mime_type_list)
    PHP_FE(swoole_clear_dns_cache,    arginfo_swoole_clear_dns_cache)
    PHP_FE(swoole_substr_unserialize, arginfo_swoole_substr_unserialize)
    PHP_FE(swoole_substr_json_decode, arginfo_swoole_substr_json_decode)
    PHP_FE(swoole_internal_call_user_shutdown_begin, arginfo_swoole_internal_call_user_shutdown_begin)
    // for test
    PHP_FE(swoole_implicit_fn,           arginfo_swoole_implicit_fn)
    // for admin server
    ZEND_FE(swoole_get_objects,          arginfo_swoole_get_objects)
    ZEND_FE(swoole_get_vm_status,        arginfo_swoole_get_vm_status)
    ZEND_FE(swoole_get_object_by_handle, arginfo_swoole_get_object_by_handle)
    ZEND_FE(swoole_name_resolver_lookup, arginfo_swoole_name_resolver_lookup)
    ZEND_FE(swoole_name_resolver_add,    arginfo_swoole_name_resolver_add)
    ZEND_FE(swoole_name_resolver_remove, arginfo_swoole_name_resolver_remove)
    PHP_FE_END /* Must be the last line in swoole_functions[] */
};

static const zend_module_dep swoole_deps[] = {
    ZEND_MOD_REQUIRED("json")
#ifdef SW_USE_MYSQLND
    ZEND_MOD_REQUIRED("mysqlnd")
#endif
#ifdef SW_SOCKETS
    ZEND_MOD_REQUIRED("sockets")
#endif
#ifdef SW_USE_CURL
    ZEND_MOD_REQUIRED("curl")
#endif
#if defined(SW_USE_PGSQL) || defined(SW_USE_ORACLE) || defined(SW_USE_SQLITE)
    ZEND_MOD_REQUIRED("pdo")
#endif

    ZEND_MOD_END
};

zend_module_entry swoole_module_entry = {
    STANDARD_MODULE_HEADER_EX,
    nullptr,
    swoole_deps,
    "swoole",
    swoole_functions,
    PHP_MINIT(swoole),
    PHP_MSHUTDOWN(swoole),
    PHP_RINIT(swoole),     //RINIT
    PHP_RSHUTDOWN(swoole), //RSHUTDOWN
    PHP_MINFO(swoole),
    PHP_SWOOLE_VERSION,
    STANDARD_MODULE_PROPERTIES
};
// clang-format on

zend_class_entry *swoole_exception_ce;
zend_object_handlers swoole_exception_handlers;

zend_class_entry *swoole_error_ce;
zend_object_handlers swoole_error_handlers;

#ifdef COMPILE_DL_SWOOLE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(swoole)
#endif

// clang-format off
/* {{{ PHP_INI
 */

PHP_INI_BEGIN()
/**
 * enable swoole coroutine
 */
STD_ZEND_INI_BOOLEAN("swoole.enable_library", "On", PHP_INI_ALL, OnUpdateBool, enable_library, zend_swoole_globals, swoole_globals)
STD_ZEND_INI_BOOLEAN("swoole.enable_fiber_mock", "Off", PHP_INI_ALL, OnUpdateBool, enable_fiber_mock, zend_swoole_globals, swoole_globals)
/**
 * enable swoole coroutine epreemptive scheduler
 */
STD_ZEND_INI_BOOLEAN("swoole.enable_preemptive_scheduler", "Off", PHP_INI_ALL, OnUpdateBool, enable_preemptive_scheduler, zend_swoole_globals, swoole_globals)
/**
 * display error
 */
STD_ZEND_INI_BOOLEAN("swoole.display_errors", "On", PHP_INI_ALL, OnUpdateBool, display_errors, zend_swoole_globals, swoole_globals)
/**
 * use short class name
 */
STD_ZEND_INI_BOOLEAN("swoole.use_shortname", "On", PHP_INI_SYSTEM, OnUpdateBool, use_shortname, zend_swoole_globals, swoole_globals)
/**
 * unix socket buffer size
 */
STD_PHP_INI_ENTRY("swoole.unixsock_buffer_size", ZEND_TOSTR(SW_SOCKET_BUFFER_SIZE), PHP_INI_ALL, OnUpdateLong, socket_buffer_size, zend_swoole_globals, swoole_globals)
PHP_INI_END()
// clang-format on

static void php_swoole_init_globals(zend_swoole_globals *swoole_globals) {
    swoole_globals->enable_library = 1;
    swoole_globals->enable_fiber_mock = 0;
    swoole_globals->enable_preemptive_scheduler = 0;
    swoole_globals->socket_buffer_size = SW_SOCKET_BUFFER_SIZE;
    swoole_globals->display_errors = 1;
    swoole_globals->use_shortname = 1;
    swoole_globals->in_autoload = nullptr;
    if (strcmp("cli", sapi_module.name) == 0 || strcmp("phpdbg", sapi_module.name) == 0 ||
        strcmp("embed", sapi_module.name) == 0 || strcmp("micro", sapi_module.name) == 0) {
        swoole_globals->cli = 1;
    }
}

void php_swoole_register_shutdown_function(const char *function) {
    php_shutdown_function_entry shutdown_function_entry;
#if PHP_VERSION_ID >= 80500
    zval function_name;
    memset(&shutdown_function_entry, 0, sizeof(php_shutdown_function_entry));
    ZVAL_STRING(&function_name, function);
    shutdown_function_entry.params = NULL;
    shutdown_function_entry.param_count = 0;
    register_user_shutdown_function(Z_STRVAL(function_name), Z_STRLEN(function_name), &shutdown_function_entry);
    zval_ptr_dtor(&function_name);
#elif PHP_VERSION_ID >= 80100
    zval function_name;
    ZVAL_STRING(&function_name, function);
    zend_fcall_info_init(
        &function_name, 0, &shutdown_function_entry.fci, &shutdown_function_entry.fci_cache, NULL, NULL);
    register_user_shutdown_function(Z_STRVAL(function_name), Z_STRLEN(function_name), &shutdown_function_entry);
#else
    zval *function_name;
    shutdown_function_entry.arg_count = 0;
    shutdown_function_entry.arguments = NULL;
    function_name = &shutdown_function_entry.function_name;
    ZVAL_STRING(function_name, function);
    register_user_shutdown_function(Z_STRVAL_P(function_name), Z_STRLEN_P(function_name), &shutdown_function_entry);
#endif
}

void php_swoole_set_global_option(HashTable *vht) {
    zval *ztmp;

#ifdef SW_DEBUG
    if (php_swoole_array_get_value(vht, "debug_mode", ztmp) && zval_is_true(ztmp)) {
        swoole_set_log_level(0);
    }
#endif
    // [EventLoop]
    // ======================================================================
    if (php_swoole_array_get_value(vht, "enable_signalfd", ztmp)) {
        SwooleG.enable_signalfd = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "enable_kqueue", ztmp)) {
        SwooleG.enable_kqueue = zval_is_true(ztmp);
    }
    // [Logger]
    // ======================================================================
    if (php_swoole_array_get_value(vht, "trace_flags", ztmp)) {
        swoole_set_trace_flags(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "log_file", ztmp)) {
        swoole_set_log_file(zend::String(ztmp).val());
    }
    if (php_swoole_array_get_value(vht, "log_level", ztmp)) {
        swoole_set_log_level(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "log_date_format", ztmp)) {
        sw_logger()->set_date_format(zend::String(ztmp).val());
    }
    if (php_swoole_array_get_value(vht, "log_date_with_microseconds", ztmp)) {
        sw_logger()->set_date_with_microseconds(zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "log_rotation", ztmp)) {
        sw_logger()->set_rotation(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "display_errors", ztmp)) {
        SWOOLE_G(display_errors) = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "print_backtrace_on_error", ztmp)) {
#if !defined(HAVE_BOOST_STACKTRACE) && !defined(HAVE_EXECINFO)
        zend_throw_exception(
            swoole_error_ce,
            "The `print_backtrace_on_error` option requires `boost stacktrace` or `execinfo.h` to be installed",
            SW_ERROR_OPERATION_NOT_SUPPORT);
#else
        SwooleG.print_backtrace_on_error = zval_is_true(ztmp);
#endif
    }
    // [DNS]
    // ======================================================================
    if (php_swoole_array_get_value(vht, "dns_server", ztmp)) {
        swoole_set_dns_server(zend::String(ztmp).to_std_string());
    }
    // [Socket]
    // ======================================================================
    auto timeout_format = [](zval *v) -> double {
        double timeout = zval_get_double(v);
        if (timeout <= 0 || timeout > INT_MAX) {
            return INT_MAX;
        } else {
            return timeout;
        }
    };
    if (php_swoole_array_get_value(vht, "socket_dns_timeout", ztmp)) {
        Socket::default_dns_timeout = timeout_format(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_connect_timeout", ztmp)) {
        Socket::default_connect_timeout = timeout_format(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_write_timeout", ztmp) ||
        php_swoole_array_get_value(vht, "socket_send_timeout", ztmp)) {
        Socket::default_write_timeout = timeout_format(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_read_timeout", ztmp) ||
        php_swoole_array_get_value(vht, "socket_recv_timeout", ztmp)) {
        Socket::default_read_timeout = timeout_format(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp)) {
        Socket::default_buffer_size = php_swoole_parse_to_size(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_timeout", ztmp)) {
        Socket::default_read_timeout = Socket::default_write_timeout = timeout_format(ztmp);
    }
    // [HTTP2]
    // ======================================================================
    if (php_swoole_array_get_value(vht, "http2_header_table_size", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE, php_swoole_parse_to_size(ztmp));
    }
    if (php_swoole_array_get_value(vht, "http2_enable_push", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH, zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "http2_max_concurrent_streams", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "http2_init_window_size", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE, php_swoole_parse_to_size(ztmp));
    }
    if (php_swoole_array_get_value(vht, "http2_max_frame_size", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE, php_swoole_parse_to_size(ztmp));
    }
    if (php_swoole_array_get_value(vht, "http2_max_header_list_size", ztmp)) {
        swoole::http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, php_swoole_parse_to_size(ztmp));
    }
}

void php_swoole_register_rshutdown_callback(swoole::Callback cb, void *private_data) {
    rshutdown_callbacks.append(cb, private_data);
}

SW_API bool php_swoole_is_enable_coroutine() {
    if (sw_server()) {
        return sw_server()->is_enable_coroutine();
    } else {
        return SwooleG.enable_coroutine;
    }
}

SW_API zend_long php_swoole_parse_to_size(zval *zv) {
    if (ZVAL_IS_STRING(zv)) {
#if PHP_VERSION_ID >= 80200
        zend_string *errstr;
        auto size = zend_ini_parse_quantity(Z_STR_P(zv), &errstr);
        if (errstr) {
            php_swoole_fatal_error(
                E_ERROR, "failed to parse '%s' to size, Error: %s", Z_STRVAL_P(zv), ZSTR_VAL(errstr));
            zend_string_release(errstr);
        }
        return size;
#else
        return zend_atol(Z_STRVAL_P(zv), Z_STRLEN_P(zv));
#endif
    } else {
        return zval_get_long(zv);
    }
}

SW_API zend_string *php_swoole_serialize(zval *zdata) {
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

SW_API bool php_swoole_unserialize(zend_string *data, zval *zv) {
    php_unserialize_data_t var_hash;
    const char *p = ZSTR_VAL(data);
    size_t l = ZSTR_LEN(data);

    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    zend_bool unserialized = php_var_unserialize(zv, (const uchar **) &p, (const uchar *) (p + l), &var_hash);
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    if (!unserialized) {
        swoole_warning("unserialize() failed, Error at offset " ZEND_LONG_FMT " of %zd bytes",
                       (zend_long)((char *) p - ZSTR_VAL(data)),
                       l);
    }
    return unserialized;
}

static void fatal_error(int code, const char *format, ...) {
    va_list args;
    va_start(args, format);
    zend_object *exception =
        zend_throw_exception(swoole_error_ce, swoole::std_string::vformat(format, args).c_str(), code);
    va_end(args);

    zend::print_error(exception, E_ERROR);

#ifdef SW_THREAD
    if (!tsrm_is_main_thread()) {
        php_swoole_thread_bailout();
    }
#endif
    swoole_exit(255);
}

static void bug_report_message_init() {
    SwooleG.bug_report_message += swoole::std_string::format("PHP_VERSION : %s\n", PHP_VERSION);
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(swoole) {
    ZEND_INIT_MODULE_GLOBALS(swoole, php_swoole_init_globals, nullptr);
    REGISTER_INI_ENTRIES();

    // clang-format off
    // MUST be on the same line for the inspection tool to recognize correctly
    SW_REGISTER_STRING_CONSTANT("SWOOLE_VERSION", SWOOLE_VERSION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_VERSION_ID", SWOOLE_VERSION_ID);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MAJOR_VERSION", SWOOLE_MAJOR_VERSION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_MINOR_VERSION", SWOOLE_MINOR_VERSION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RELEASE_VERSION", SWOOLE_RELEASE_VERSION);
    SW_REGISTER_STRING_CONSTANT("SWOOLE_EXTRA_VERSION", SWOOLE_EXTRA_VERSION);
#ifndef SW_DEBUG
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_DEBUG", 0);
#else
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_DEBUG", 1);
#endif

#ifdef SW_HAVE_COMPRESSION
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_HAVE_COMPRESSION", 1);
#endif
#ifdef SW_HAVE_ZLIB
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_HAVE_ZLIB", 1);
#endif
#ifdef SW_HAVE_BROTLI
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_HAVE_BROTLI", 1);
#endif
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_USE_HTTP2", 1);
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_USE_SHORTNAME", SWOOLE_G(use_shortname));

    /**
     * socket type
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_STREAM", SW_SOCK_UNIX_STREAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_RAW", SW_SOCK_RAW);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SOCK_RAW6", SW_SOCK_RAW6);

    /**
     * simple socket type alias
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TCP", SW_SOCK_TCP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TCP6", SW_SOCK_TCP6);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_UDP", SW_SOCK_UDP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_UDP6", SW_SOCK_UDP6);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_UNIX_STREAM", SW_SOCK_UNIX_STREAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RAW", SW_SOCK_RAW);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_RAW6", SW_SOCK_RAW6);

    /**
     * simple api
     */
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_SOCK_SYNC", 0);
    SW_REGISTER_BOOL_CONSTANT("SWOOLE_SOCK_ASYNC", 1);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_SYNC", SW_FLAG_SYNC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ASYNC", SW_FLAG_ASYNC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_KEEP", SW_FLAG_KEEP);

#ifdef SW_USE_OPENSSL
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL", SW_SOCK_SSL);

    /**
     * SSL methods
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_METHOD", SW_SSLv3_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_SERVER_METHOD", SW_SSLv3_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_CLIENT_METHOD", SW_SSLv3_CLIENT_METHOD);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_METHOD", SW_TLSv1_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_SERVER_METHOD", SW_TLSv1_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_CLIENT_METHOD", SW_TLSv1_CLIENT_METHOD);

#ifdef TLS1_1_VERSION
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_METHOD", SW_TLSv1_1_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_SERVER_METHOD", SW_TLSv1_1_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_CLIENT_METHOD", SW_TLSv1_1_CLIENT_METHOD);
#endif

#ifdef TLS1_2_VERSION
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_METHOD", SW_TLSv1_2_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_SERVER_METHOD", SW_TLSv1_2_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_CLIENT_METHOD", SW_TLSv1_2_CLIENT_METHOD);
#endif

#ifdef SW_SUPPORT_DTLS
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DTLS_SERVER_METHOD", SW_DTLS_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_DTLS_CLIENT_METHOD", SW_DTLS_CLIENT_METHOD);
#endif

    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_METHOD", SW_SSLv23_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_SERVER_METHOD", SW_SSLv23_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_CLIENT_METHOD", SW_SSLv23_CLIENT_METHOD);
    /* SSLv23_method have been renamed to TLS_method */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLS_METHOD", SW_SSLv23_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLS_SERVER_METHOD", SW_SSLv23_SERVER_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TLS_CLIENT_METHOD", SW_SSLv23_CLIENT_METHOD);

    /**
     * SSL protocols
     */
#ifdef HAVE_SSL3
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_SSLv3", SW_SSL_SSLv3);
#endif
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_TLSv1", SW_SSL_TLSv1);

#ifdef TLS1_1_VERSION
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_TLSv1_1", SW_SSL_TLSv1_1);
#endif

#ifdef TLS1_2_VERSION
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_TLSv1_2", SW_SSL_TLSv1_2);
#endif

#ifdef TLS1_3_VERSION
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_TLSv1_3", SW_SSL_TLSv1_3);
#endif

#ifdef SW_SUPPORT_DTLS
    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_DTLS", SW_SSL_DTLS);
#endif

    SW_REGISTER_LONG_CONSTANT("SWOOLE_SSL_SSLv2", SW_SSL_SSLv2);
#endif

    SW_REGISTER_LONG_CONSTANT("SWOOLE_EVENT_READ", SW_EVENT_READ);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_EVENT_WRITE", SW_EVENT_WRITE);

    /**
     * Register ERROR types
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_STRERROR_SYSTEM", SW_STRERROR_SYSTEM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_STRERROR_GAI", SW_STRERROR_GAI);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_STRERROR_DNS", SW_STRERROR_DNS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_STRERROR_SWOOLE", SW_STRERROR_SWOOLE);

    /**
     * Register ERROR constants
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_MALLOC_FAIL", SW_ERROR_MALLOC_FAIL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SYSTEM_CALL_FAIL", SW_ERROR_SYSTEM_CALL_FAIL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PHP_FATAL_ERROR", SW_ERROR_PHP_FATAL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_NAME_TOO_LONG", SW_ERROR_NAME_TOO_LONG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_INVALID_PARAMS", SW_ERROR_INVALID_PARAMS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_QUEUE_FULL", SW_ERROR_QUEUE_FULL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_OPERATION_NOT_SUPPORT", SW_ERROR_OPERATION_NOT_SUPPORT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PROTOCOL_ERROR", SW_ERROR_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WRONG_OPERATION", SW_ERROR_WRONG_OPERATION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PHP_RUNTIME_NOTICE", SW_ERROR_PHP_RUNTIME_NOTICE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_FOR_TEST", SW_ERROR_FOR_TEST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_NO_PAYLOAD", SW_ERROR_NO_PAYLOAD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_UNDEFINED_BEHAVIOR", SW_ERROR_UNDEFINED_BEHAVIOR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_NOT_THREAD_SAFETY", SW_ERROR_NOT_THREAD_SAFETY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_FILE_NOT_EXIST", SW_ERROR_FILE_NOT_EXIST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_FILE_TOO_LARGE", SW_ERROR_FILE_TOO_LARGE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_FILE_EMPTY", SW_ERROR_FILE_EMPTY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DNSLOOKUP_DUPLICATE_REQUEST", SW_ERROR_DNSLOOKUP_DUPLICATE_REQUEST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED", SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT", SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DNSLOOKUP_UNSUPPORTED", SW_ERROR_DNSLOOKUP_UNSUPPORTED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DNSLOOKUP_NO_SERVER", SW_ERROR_DNSLOOKUP_NO_SERVER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_BAD_IPV6_ADDRESS", SW_ERROR_BAD_IPV6_ADDRESS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_UNREGISTERED_SIGNAL", SW_ERROR_UNREGISTERED_SIGNAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_BAD_HOST_ADDR", SW_ERROR_BAD_HOST_ADDR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_EVENT_REMOVE_FAILED", SW_ERROR_EVENT_REMOVE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_EVENT_ADD_FAILED", SW_ERROR_EVENT_ADD_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_EVENT_UPDATE_FAILED", SW_ERROR_EVENT_UPDATE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_CLOSED_BY_SERVER", SW_ERROR_SESSION_CLOSED_BY_SERVER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_CLOSED_BY_CLIENT", SW_ERROR_SESSION_CLOSED_BY_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_CLOSING", SW_ERROR_SESSION_CLOSING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_CLOSED", SW_ERROR_SESSION_CLOSED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_NOT_EXIST", SW_ERROR_SESSION_NOT_EXIST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_INVALID_ID", SW_ERROR_SESSION_INVALID_ID);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_DISCARD_TIMEOUT_DATA", SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SESSION_DISCARD_DATA", SW_ERROR_SESSION_DISCARD_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_OUTPUT_BUFFER_OVERFLOW", SW_ERROR_OUTPUT_BUFFER_OVERFLOW);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_OUTPUT_SEND_YIELD", SW_ERROR_OUTPUT_SEND_YIELD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_NOT_READY", SW_ERROR_SSL_NOT_READY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_CANNOT_USE_SENFILE", SW_ERROR_SSL_CANNOT_USE_SENFILE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_EMPTY_PEER_CERTIFICATE", SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_VERIFY_FAILED", SW_ERROR_SSL_VERIFY_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_BAD_CLIENT", SW_ERROR_SSL_BAD_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_BAD_PROTOCOL", SW_ERROR_SSL_BAD_PROTOCOL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_RESET", SW_ERROR_SSL_RESET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_HANDSHAKE_FAILED", SW_ERROR_SSL_HANDSHAKE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SSL_CREATE_CONTEXT_FAILED", SW_ERROR_SSL_CREATE_CONTEXT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE", SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PACKAGE_LENGTH_NOT_FOUND", SW_ERROR_PACKAGE_LENGTH_NOT_FOUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_DATA_LENGTH_TOO_LARGE", SW_ERROR_DATA_LENGTH_TOO_LARGE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_PACKAGE_MALFORMED_DATA", SW_ERROR_PACKAGE_MALFORMED_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_TASK_PACKAGE_TOO_BIG", SW_ERROR_TASK_PACKAGE_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_TASK_DISPATCH_FAIL", SW_ERROR_TASK_DISPATCH_FAIL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_TASK_TIMEOUT", SW_ERROR_TASK_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP2_STREAM_ID_TOO_BIG", SW_ERROR_HTTP2_STREAM_ID_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP2_STREAM_NO_HEADER", SW_ERROR_HTTP2_STREAM_NO_HEADER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP2_STREAM_NOT_FOUND", SW_ERROR_HTTP2_STREAM_NOT_FOUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP2_STREAM_IGNORE", SW_ERROR_HTTP2_STREAM_IGNORE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED", SW_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_AIO_BAD_REQUEST", SW_ERROR_AIO_BAD_REQUEST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_AIO_CANCELED", SW_ERROR_AIO_CANCELED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_AIO_TIMEOUT", SW_ERROR_AIO_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CLIENT_NO_CONNECTION", SW_ERROR_CLIENT_NO_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKET_CLOSED", SW_ERROR_SOCKET_CLOSED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKET_POLL_TIMEOUT", SW_ERROR_SOCKET_POLL_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKS5_UNSUPPORT_VERSION", SW_ERROR_SOCKS5_UNSUPPORT_VERSION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKS5_UNSUPPORT_METHOD", SW_ERROR_SOCKS5_UNSUPPORT_METHOD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKS5_AUTH_FAILED", SW_ERROR_SOCKS5_AUTH_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKS5_SERVER_ERROR", SW_ERROR_SOCKS5_SERVER_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SOCKS5_HANDSHAKE_FAILED", SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_ERROR", SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_INVALID_PROTOCOL", SW_ERROR_HTTP_INVALID_PROTOCOL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_FAILED", SW_ERROR_HTTP_PROXY_HANDSHAKE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE", SW_ERROR_HTTP_PROXY_BAD_RESPONSE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_CONFLICT_HEADER", SW_ERROR_HTTP_CONFLICT_HEADER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_CONTEXT_UNAVAILABLE", SW_ERROR_HTTP_CONTEXT_UNAVAILABLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_HTTP_COOKIE_UNAVAILABLE", SW_ERROR_HTTP_COOKIE_UNAVAILABLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_BAD_CLIENT", SW_ERROR_WEBSOCKET_BAD_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_BAD_OPCODE", SW_ERROR_WEBSOCKET_BAD_OPCODE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_UNCONNECTED", SW_ERROR_WEBSOCKET_UNCONNECTED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_HANDSHAKE_FAILED", SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_PACK_FAILED", SW_ERROR_WEBSOCKET_PACK_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_UNPACK_FAILED", SW_ERROR_WEBSOCKET_UNPACK_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_WEBSOCKET_INCOMPLETE_PACKET", SW_ERROR_WEBSOCKET_INCOMPLETE_PACKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT", SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_TOO_MANY_SOCKET", SW_ERROR_SERVER_TOO_MANY_SOCKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_WORKER_TERMINATED", SW_ERROR_SERVER_WORKER_TERMINATED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_INVALID_LISTEN_PORT", SW_ERROR_SERVER_INVALID_LISTEN_PORT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_TOO_MANY_LISTEN_PORT", SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_PIPE_BUFFER_FULL", SW_ERROR_SERVER_PIPE_BUFFER_FULL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_NO_IDLE_WORKER", SW_ERROR_SERVER_NO_IDLE_WORKER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_ONLY_START_ONE", SW_ERROR_SERVER_ONLY_START_ONE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_SEND_IN_MASTER", SW_ERROR_SERVER_SEND_IN_MASTER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_INVALID_REQUEST", SW_ERROR_SERVER_INVALID_REQUEST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_CONNECT_FAIL", SW_ERROR_SERVER_CONNECT_FAIL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_INVALID_COMMAND", SW_ERROR_SERVER_INVALID_COMMAND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_IS_NOT_REGULAR_FILE", SW_ERROR_SERVER_IS_NOT_REGULAR_FILE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_SEND_TO_WOKER_TIMEOUT", SW_ERROR_SERVER_SEND_TO_WOKER_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_INVALID_CALLBACK", SW_ERROR_SERVER_INVALID_CALLBACK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_UNRELATED_THREAD", SW_ERROR_SERVER_UNRELATED_THREAD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_WORKER_EXIT_TIMEOUT", SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA", SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_SERVER_WORKER_UNPROCESSED_DATA", SW_ERROR_SERVER_WORKER_UNPROCESSED_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_OUT_OF_COROUTINE", SW_ERROR_CO_OUT_OF_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_HAS_BEEN_BOUND", SW_ERROR_CO_HAS_BEEN_BOUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_HAS_BEEN_DISCARDED", SW_ERROR_CO_HAS_BEEN_DISCARDED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_MUTEX_DOUBLE_UNLOCK", SW_ERROR_CO_MUTEX_DOUBLE_UNLOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_BLOCK_OBJECT_LOCKED", SW_ERROR_CO_BLOCK_OBJECT_LOCKED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_BLOCK_OBJECT_WAITING", SW_ERROR_CO_BLOCK_OBJECT_WAITING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_YIELD_FAILED", SW_ERROR_CO_YIELD_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_GETCONTEXT_FAILED", SW_ERROR_CO_GETCONTEXT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_SWAPCONTEXT_FAILED", SW_ERROR_CO_SWAPCONTEXT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_MAKECONTEXT_FAILED", SW_ERROR_CO_MAKECONTEXT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_IOCPINIT_FAILED", SW_ERROR_CO_IOCPINIT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_PROTECT_STACK_FAILED", SW_ERROR_CO_PROTECT_STACK_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_STD_THREAD_LINK_ERROR", SW_ERROR_CO_STD_THREAD_LINK_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_DISABLED_MULTI_THREAD", SW_ERROR_CO_DISABLED_MULTI_THREAD);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_CANNOT_CANCEL", SW_ERROR_CO_CANNOT_CANCEL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_NOT_EXISTS", SW_ERROR_CO_NOT_EXISTS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_CANCELED", SW_ERROR_CO_CANCELED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_TIMEDOUT", SW_ERROR_CO_TIMEDOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_ERROR_CO_SOCKET_CLOSE_WAIT", SW_ERROR_CO_SOCKET_CLOSE_WAIT);

    /**
     * trace log
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_SERVER", SW_TRACE_SERVER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CLIENT", SW_TRACE_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_BUFFER", SW_TRACE_BUFFER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CONN", SW_TRACE_CONN);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_EVENT", SW_TRACE_EVENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_WORKER", SW_TRACE_WORKER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_MEMORY", SW_TRACE_MEMORY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_REACTOR", SW_TRACE_REACTOR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_PHP", SW_TRACE_PHP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_HTTP", SW_TRACE_HTTP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_HTTP2", SW_TRACE_HTTP2);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_EOF_PROTOCOL", SW_TRACE_EOF_PROTOCOL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_LENGTH_PROTOCOL", SW_TRACE_LENGTH_PROTOCOL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CLOSE", SW_TRACE_CLOSE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_WEBSOCKET", SW_TRACE_WEBSOCKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_REDIS_CLIENT", SW_TRACE_REDIS_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_MYSQL_CLIENT", SW_TRACE_MYSQL_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_HTTP_CLIENT", SW_TRACE_HTTP_CLIENT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_AIO", SW_TRACE_AIO);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_SSL", SW_TRACE_SSL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_NORMAL", SW_TRACE_NORMAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CHANNEL", SW_TRACE_CHANNEL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_TIMER", SW_TRACE_TIMER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_SOCKET", SW_TRACE_SOCKET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_COROUTINE", SW_TRACE_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CONTEXT", SW_TRACE_CONTEXT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_HTTP_SERVER", SW_TRACE_CO_HTTP_SERVER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_TABLE", SW_TRACE_TABLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_CURL", SW_TRACE_CO_CURL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CARES", SW_TRACE_CARES);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_ZLIB", SW_TRACE_ZLIB);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_PGSQL", SW_TRACE_CO_PGSQL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_ODBC", SW_TRACE_CO_ODBC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_ORACLE", SW_TRACE_CO_ORACLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_CO_SQLITE", SW_TRACE_CO_SQLITE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_TRACE_ALL", SW_TRACE_ALL);

    /**
     * log level
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_DEBUG", SW_LOG_DEBUG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_TRACE", SW_LOG_TRACE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_INFO", SW_LOG_INFO);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_NOTICE", SW_LOG_NOTICE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_WARNING", SW_LOG_WARNING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ERROR", SW_LOG_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_NONE", SW_LOG_NONE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ROTATION_SINGLE", SW_LOG_ROTATION_SINGLE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ROTATION_MONTHLY", SW_LOG_ROTATION_MONTHLY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ROTATION_DAILY", SW_LOG_ROTATION_DAILY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ROTATION_HOURLY", SW_LOG_ROTATION_HOURLY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_LOG_ROTATION_EVERY_MINUTE", SW_LOG_ROTATION_EVERY_MINUTE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_NONE", SW_IPC_NONE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_UNIXSOCK", SW_IPC_UNIXSOCK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IPC_SOCKET", SW_IPC_SOCKET);

    /**
     * limit
     */
    SW_REGISTER_LONG_CONSTANT("SWOOLE_IOV_MAX", IOV_MAX);

    /**
     * iouring
     */
#ifdef SW_USE_IOURING
     SW_REGISTER_LONG_CONSTANT("SWOOLE_IOURING_DEFAULT", SW_IOURING_DEFAULT);
     SW_REGISTER_LONG_CONSTANT("SWOOLE_IOURING_SQPOLL", SW_IOURING_SQPOLL);
#endif

    // clang-format on

    if (SWOOLE_G(use_shortname)) {
        SW_FUNCTION_ALIAS(
            CG(function_table), "swoole_coroutine_create", CG(function_table), "go", arginfo_swoole_coroutine_create);
        SW_FUNCTION_ALIAS(
            CG(function_table), "swoole_coroutine_defer", CG(function_table), "defer", arginfo_swoole_coroutine_defer);
    }

    swoole_init();

    // init bug report message
    bug_report_message_init();

    SW_INIT_CLASS_ENTRY_EX2(
        swoole_exception, "Swoole\\Exception", nullptr, nullptr, zend_ce_exception, zend_get_std_object_handlers());

    SW_INIT_CLASS_ENTRY_EX2(
        swoole_error, "Swoole\\Error", nullptr, nullptr, zend_ce_error, zend_get_std_object_handlers());

    /** <Sort by dependency> **/
    php_swoole_event_minit(module_number);
    // base
    php_swoole_atomic_minit(module_number);
    php_swoole_lock_minit(module_number);
    php_swoole_process_minit(module_number);
    php_swoole_process_pool_minit(module_number);
    php_swoole_table_minit(module_number);
    php_swoole_timer_minit(module_number);
    // coroutine
    php_swoole_coroutine_minit(module_number);
    php_swoole_coroutine_system_minit(module_number);
    php_swoole_coroutine_scheduler_minit(module_number);
    php_swoole_coroutine_lock_minit(module_number);
    php_swoole_channel_coro_minit(module_number);
    php_swoole_runtime_minit(module_number);
    // client
    php_swoole_socket_coro_minit(module_number);
    php_swoole_client_minit(module_number);
    php_swoole_client_async_minit(module_number);
    php_swoole_client_coro_minit(module_number);
    php_swoole_http_client_coro_minit(module_number);
    php_swoole_http2_client_coro_minit(module_number);
    // server
    php_swoole_server_minit(module_number);
    php_swoole_server_port_minit(module_number);
    php_swoole_http_request_minit(module_number);
    php_swoole_http_response_minit(module_number);
    php_swoole_http_cookie_minit(module_number);
    php_swoole_http_server_minit(module_number);
    php_swoole_http_server_coro_minit(module_number);
    php_swoole_websocket_server_minit(module_number);
    php_swoole_redis_server_minit(module_number);
    php_swoole_name_resolver_minit(module_number);
#ifdef SW_USE_PGSQL
    php_swoole_pgsql_minit(module_number);
#endif
#ifdef SW_USE_ODBC
    php_swoole_odbc_minit(module_number);
#endif
#ifdef SW_USE_ORACLE
    php_swoole_oracle_minit(module_number);
#endif
#ifdef SW_USE_SQLITE
    php_swoole_sqlite_minit(module_number);
#endif
#ifdef SW_THREAD
    php_swoole_thread_minit(module_number);
    php_swoole_thread_atomic_minit(module_number);
    php_swoole_thread_lock_minit(module_number);
    php_swoole_thread_barrier_minit(module_number);
    php_swoole_thread_queue_minit(module_number);
    php_swoole_thread_map_minit(module_number);
    php_swoole_thread_arraylist_minit(module_number);
#endif

    SwooleG.fatal_error = fatal_error;
    Socket::default_buffer_size = SWOOLE_G(socket_buffer_size);
    SwooleG.dns_cache_refresh_time = 60;

    // enable pcre.jit and use swoole extension on MacOS will lead to coredump, disable it temporarily
#if defined(PHP_PCRE_VERSION) && defined(HAVE_PCRE_JIT_SUPPORT) && __MACH__ && !defined(SW_DEBUG)
    PCRE_G(jit) = 0;
#endif

    zend::known_strings_init();

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(swoole) {
    zend::known_strings_dtor();

    php_swoole_runtime_mshutdown();
    php_swoole_websocket_server_mshutdown();
#ifdef SW_USE_PGSQL
    php_swoole_pgsql_mshutdown();
#endif

#ifdef SW_USE_ORACLE
    php_swoole_oracle_mshutdown();
#endif

#ifdef SW_USE_SQLITE
    php_swoole_sqlite_mshutdown();
#endif

    swoole_clean();

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(swoole) {
    char buf[64];
    php_info_print_table_start();
    php_info_print_table_header(2, "Swoole", "enabled");
    php_info_print_table_row(2, "Author", "Swoole Team <team@swoole.com>");
    php_info_print_table_row(2, "Version", SWOOLE_VERSION);
    snprintf(buf, sizeof(buf), "%s %s", __DATE__, __TIME__);
    php_info_print_table_row(2, "Built", buf);

#if SW_BYTE_ORDER == SW_LITTLE_ENDIAN
    php_info_print_table_row(2, "host byte order", "little endian");
#else
    php_info_print_table_row(2, "host byte order", "big endian");
#endif

#if defined(SW_USE_THREAD_CONTEXT)
    php_info_print_table_row(2, "coroutine", "enabled with thread context");
#elif defined(SW_USE_ASM_CONTEXT)
    php_info_print_table_row(2, "coroutine", "enabled with boost asm context");
#else
    php_info_print_table_row(2, "coroutine", "enabled with ucontext");
#endif
#ifdef SW_DEBUG
    php_info_print_table_row(2, "debug", "enabled");
#endif
#ifdef SW_LOG_TRACE_OPEN
    php_info_print_table_row(2, "trace_log", "enabled");
#endif
#ifdef HAVE_EPOLL
    php_info_print_table_row(2, "epoll", "enabled");
#endif
#ifdef HAVE_EVENTFD
    php_info_print_table_row(2, "eventfd", "enabled");
#endif
#ifdef SW_THREAD
    php_info_print_table_row(2, "thread", "enabled");
#endif
#ifdef HAVE_SIGNALFD
    php_info_print_table_row(2, "signalfd", "enabled");
#endif
#ifdef SW_USE_ACCEPT4
    php_info_print_table_row(2, "accept4", "enabled");
#endif
#ifdef HAVE_CPU_AFFINITY
    php_info_print_table_row(2, "cpu_affinity", "enabled");
#endif
#ifdef HAVE_SPINLOCK
    php_info_print_table_row(2, "spinlock", "enabled");
#endif
#ifdef HAVE_RWLOCK
    php_info_print_table_row(2, "rwlock", "enabled");
#endif
#ifdef SW_SOCKETS
    php_info_print_table_row(2, "sockets", "enabled");
#endif
#ifdef SW_USE_OPENSSL
#ifdef OPENSSL_VERSION_TEXT
    php_info_print_table_row(2, "openssl", OPENSSL_VERSION_TEXT);
#else
    php_info_print_table_row(2, "openssl", "enabled");
#endif
#ifdef SW_SUPPORT_DTLS
    php_info_print_table_row(2, "dtls", "enabled");
#endif
#endif
    php_info_print_table_row(2, "http2", "enabled");
    php_info_print_table_row(2, "json", "enabled");
#ifdef SW_USE_CURL
    php_info_print_table_row(2, "curl-native", "enabled");
    curl_version_info_data *d = curl_version_info(CURLVERSION_NOW);
    php_info_print_table_row(2, "curl-version", d->version);
#endif
#ifdef SW_USE_CARES
    php_info_print_table_row(2, "c-ares", ares_version(nullptr));
#endif
#ifdef SW_HAVE_ZLIB
#ifdef ZLIB_VERSION
    php_info_print_table_row(2, "zlib", ZLIB_VERSION);
#else
    php_info_print_table_row(2, "zlib", "enabled");
#endif
#endif
#ifdef SW_HAVE_BROTLI
    snprintf(buf, sizeof(buf), "E%u/D%u", BrotliEncoderVersion(), BrotliDecoderVersion());
    php_info_print_table_row(2, "brotli", buf);
#endif
#ifdef SW_HAVE_ZSTD
#ifdef ZSTD_VERSION_NUMBER
    php_info_print_table_row(2, "zstd", ZSTD_VERSION_STRING);
#else
    php_info_print_table_row(2, "zstd", "enabled");
#endif
#endif
#ifdef HAVE_MUTEX_TIMEDLOCK
    php_info_print_table_row(2, "mutex_timedlock", "enabled");
#endif
#ifdef HAVE_PTHREAD_BARRIER
    php_info_print_table_row(2, "pthread_barrier", "enabled");
#endif
#ifdef HAVE_FUTEX
    php_info_print_table_row(2, "futex", "enabled");
#endif
#ifdef SW_USE_MYSQLND
    php_info_print_table_row(2, "mysqlnd", "enabled");
#endif
#ifdef SW_USE_JEMALLOC
    php_info_print_table_row(2, "jemalloc", "enabled");
#endif
#ifdef SW_USE_TCMALLOC
    php_info_print_table_row(2, "tcmalloc", "enabled");
#endif
#ifdef SW_USE_PGSQL
    php_info_print_table_row(2, "coroutine_pgsql", "enabled");
#endif
#ifdef SW_USE_ODBC
    php_info_print_table_row(2, "coroutine_odbc", "enabled");
#endif
#ifdef SW_USE_ORACLE
    php_info_print_table_row(2, "coroutine_oracle", "enabled");
#endif
#ifdef SW_USE_SQLITE
    php_info_print_table_row(2, "coroutine_sqlite", "enabled");
#endif
#ifdef SW_USE_IOURING
    php_info_print_table_row(2, "io_uring", "enabled");
#endif
#ifdef HAVE_BOOST_STACKTRACE
    php_info_print_table_row(2, "boost stacktrace", "enabled");
#elif defined(HAVE_EXECINFO)
    php_info_print_table_row(2, "execinfo", "enabled");
#endif
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */

static void *_sw_emalloc(size_t size) {
    return emalloc(size);
}

static void *_sw_ecalloc(size_t nmemb, size_t size) {
    return ecalloc(nmemb, size);
}

static void *_sw_erealloc(void *address, size_t size) {
    return erealloc(address, size);
}

static void _sw_efree(void *address) {
    efree(address);
}

static void *_sw_zend_string_malloc(size_t size) {
    zend_string *str = zend_string_alloc(size, 0);
    if (str == nullptr) {
        return nullptr;
    }
    return str->val;
}

static void *_sw_zend_string_calloc(size_t nmemb, size_t size) {
    void *mem = _sw_zend_string_malloc(nmemb * size);
    if (mem) {
        sw_memset_zero(mem, size);
    }
    return mem;
}

static void *_sw_zend_string_realloc(void *address, size_t size) {
    zend_string *str = zend_string_realloc(zend::fetch_zend_string_by_val(address), size, 0);
    if (str == nullptr) {
        return nullptr;
    }
    return str->val;
}

static void _sw_zend_string_free(void *address) {
    zend_string_free(zend::fetch_zend_string_by_val(address));
}

static swoole::Allocator php_allocator{
    _sw_emalloc,
    _sw_ecalloc,
    _sw_erealloc,
    _sw_efree,
};

static swoole::Allocator zend_string_allocator{
    _sw_zend_string_malloc,
    _sw_zend_string_calloc,
    _sw_zend_string_realloc,
    _sw_zend_string_free,
};

const swoole::Allocator *sw_php_allocator() {
    return &php_allocator;
}

const swoole::Allocator *sw_zend_string_allocator() {
    return &zend_string_allocator;
}

void sw_php_exit(int status) {
    EG(exit_status) = status;
#ifdef SW_THREAD
    php_swoole_thread_bailout();
#else
    zend_bailout();
#endif
}

bool sw_zval_is_serializable(zval *struc) {
again:
    switch (Z_TYPE_P(struc)) {
    case IS_OBJECT: {
        if (Z_OBJCE_P(struc)->ce_flags & ZEND_ACC_NOT_SERIALIZABLE) {
            return false;
        }
        break;
    }
    case IS_ARRAY: {
        zval *elem;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(struc), elem) {
            if (!sw_zval_is_serializable(elem)) {
                return false;
            }
        }
        ZEND_HASH_FOREACH_END();
        break;
    }
    case IS_REFERENCE:
        struc = Z_REFVAL_P(struc);
        goto again;
    default:
        break;
    }
    return true;
}

static void sw_after_fork(void *args) {
#ifdef ZEND_MAX_EXECUTION_TIMERS
    zend_max_execution_timer_init();
#endif
}

PHP_RINIT_FUNCTION(swoole) {
    if (!SWOOLE_G(cli)) {
        return SUCCESS;
    }

    SWOOLE_G(req_status) = PHP_SWOOLE_RINIT_BEGIN;

    php_swoole_register_shutdown_function("swoole_internal_call_user_shutdown_begin");

    if (SWOOLE_G(enable_library)
#ifdef ZEND_COMPILE_PRELOAD
        /* avoid execution of the code during RINIT of preloader */
        && !(CG(compiler_options) & ZEND_COMPILE_PRELOAD)
#endif
    ) {
        // https://github.com/swoole/swoole-src/issues/5182
        /**
         * xdebug will hook zend_execute_ex to xdebug_execute_ex.
         * This would cause php_swoole_load_library function not to execute correctly, so it must be replaced
         * with the execute_ex function.
         */
        void (*old_zend_execute_ex)(zend_execute_data * execute_data) = nullptr;
        if (UNEXPECTED(zend_execute_ex != execute_ex)) {
            old_zend_execute_ex = zend_execute_ex;
            zend_execute_ex = execute_ex;
        }

        php_swoole_load_library();

        if (UNEXPECTED(old_zend_execute_ex)) {
            zend_execute_ex = old_zend_execute_ex;
            old_zend_execute_ex = nullptr;
        }
    }

#ifdef ZEND_SIGNALS
    /* Disable warning even in ZEND_DEBUG because we may register our own signal handlers  */
    SIGG(check) = 0;
#endif

    swoole_add_hook(SW_GLOBAL_HOOK_AFTER_FORK, sw_after_fork, 0);

    php_swoole_http_server_rinit();
    php_swoole_websocket_server_rinit();
    php_swoole_coroutine_rinit();
    php_swoole_runtime_rinit();
#ifdef SW_USE_ORACLE
    php_swoole_oracle_rinit();
#endif
#ifdef SW_THREAD
    php_swoole_thread_rinit();
#endif

    SWOOLE_G(req_status) = PHP_SWOOLE_RINIT_END;

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(swoole) {
    if (!SWOOLE_G(cli)) {
        return SUCCESS;
    }

    SWOOLE_G(req_status) = PHP_SWOOLE_RSHUTDOWN_BEGIN;

    rshutdown_callbacks.execute();

    php_swoole_server_rshutdown();
    php_swoole_http_server_rshutdown();
    php_swoole_websocket_server_rshutdown();
    php_swoole_async_coro_rshutdown();
    php_swoole_redis_server_rshutdown();
    php_swoole_coroutine_rshutdown();
    php_swoole_coroutine_scheduler_rshutdown();
    php_swoole_timer_rshutdown();
    php_swoole_runtime_rshutdown();
    php_swoole_process_rshutdown();
#ifdef SW_THREAD
    php_swoole_thread_rshutdown();
#endif

    swoole_event_free();

    SWOOLE_G(req_status) = PHP_SWOOLE_RSHUTDOWN_END;

#ifdef PHP_STREAM_FLAG_NO_CLOSE
    auto php_swoole_set_stdio_no_close = [](const char *name, size_t name_len) {
        zval *zstream;
        php_stream *stream;

        zstream = zend_get_constant_str(name, name_len);
        if (!zstream) {
            return;
        }
        stream = (php_stream *) zend_fetch_resource2_ex((zstream), NULL, php_file_le_stream(), php_file_le_pstream());
        if (!stream) {
            return;
        }
        stream->flags |= PHP_STREAM_FLAG_NO_CLOSE;
    };
    /* do not close the stdout and stderr */
    php_swoole_set_stdio_no_close(ZEND_STRL("STDOUT"));
    php_swoole_set_stdio_no_close(ZEND_STRL("STDERR"));
#endif

    return SUCCESS;
}

static PHP_FUNCTION(swoole_version) {
    RETURN_STRING(SWOOLE_VERSION);
}

static uint32_t hashkit_one_at_a_time(const char *key, size_t key_length) {
    const char *ptr = key;
    uint32_t value = 0;

    while (key_length--) {
        uint32_t val = (uint32_t) *ptr++;
        value += val;
        value += (value << 10);
        value ^= (value >> 6);
    }
    value += (value << 3);
    value ^= (value >> 11);
    value += (value << 15);

    return value;
}

static PHP_FUNCTION(swoole_hashcode) {
    char *data;
    size_t l_data;
    zend_long type = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(data, l_data)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    switch (type) {
    case 0:
        RETURN_LONG(zend_hash_func(data, l_data));
    case 1:
        RETURN_LONG(hashkit_one_at_a_time(data, l_data));
    default:
        RETURN_FALSE;
    }
}

static PHP_FUNCTION(swoole_clear_error) {
    swoole_set_last_error(0);
}

PHP_FUNCTION(swoole_last_error) {
    RETURN_LONG(swoole_get_last_error());
}

static PHP_FUNCTION(swoole_cpu_num) {
    RETURN_LONG(SW_CPU_NUM);
}

static PHP_FUNCTION(swoole_strerror) {
    zend_long swoole_errno;
    zend_long error_type = SW_STRERROR_SYSTEM;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(swoole_errno)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(error_type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (error_type == SW_STRERROR_GAI) {
        RETURN_STRING(gai_strerror(swoole_errno));
    } else if (error_type == SW_STRERROR_DNS) {
        RETURN_STRING(hstrerror(swoole_errno));
    } else if (error_type == SW_STRERROR_SWOOLE || (swoole_errno > SW_ERROR_BEGIN && swoole_errno < SW_ERROR_END)) {
        RETURN_STRING(swoole_strerror(swoole_errno));
    } else {
        RETURN_STRING(strerror(swoole_errno));
    }
}

static PHP_FUNCTION(swoole_error_log) {
    char *msg;
    size_t l_msg;
    zend_long level;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_LONG(level)
    Z_PARAM_STRING(msg, l_msg)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    sw_logger()->put(level, msg, l_msg);
}

static PHP_FUNCTION(swoole_error_log_ex) {
    char *msg;
    size_t l_msg;
    zend_long level, error;

    ZEND_PARSE_PARAMETERS_START(3, 3)
    Z_PARAM_LONG(level)
    Z_PARAM_LONG(error)
    Z_PARAM_STRING(msg, l_msg)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_error_log(level, (int) error, "%.*s", (int) l_msg, msg);
}

static PHP_FUNCTION(swoole_ignore_error) {
    zend_long error;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(error)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_ignore_error(error);
}

static PHP_FUNCTION(swoole_mime_type_add) {
    zend_string *suffix;
    zend_string *mime_type;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STR(suffix)
    Z_PARAM_STR(mime_type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(swoole::mime_type::add(ZSTR_VAL(suffix), ZSTR_VAL(mime_type)));
}

static PHP_FUNCTION(swoole_mime_type_set) {
    zend_string *suffix;
    zend_string *mime_type;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STR(suffix)
    Z_PARAM_STR(mime_type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole::mime_type::set(ZSTR_VAL(suffix), ZSTR_VAL(mime_type));
}

static PHP_FUNCTION(swoole_mime_type_delete) {
    zend_string *suffix;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STR(suffix)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(swoole::mime_type::del(ZSTR_VAL(suffix)));
}

static PHP_FUNCTION(swoole_mime_type_get) {
    zend_string *filename;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STR(filename)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_STRING(swoole::mime_type::get(ZSTR_VAL(filename)).c_str());
}

static PHP_FUNCTION(swoole_mime_type_exists) {
    zend_string *filename;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STR(filename)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(swoole::mime_type::exists(ZSTR_VAL(filename)));
}

static PHP_FUNCTION(swoole_mime_type_list) {
    array_init(return_value);
    for (auto &i : swoole::mime_type::list()) {
        add_next_index_string(return_value, i.second.c_str());
    }
}

static PHP_FUNCTION(swoole_errno) {
    RETURN_LONG(errno);
}

PHP_FUNCTION(swoole_set_process_name) {
    zend_function *cli_set_process_title =
        (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("cli_set_process_title"));
    if (!cli_set_process_title) {
        php_swoole_fatal_error(E_WARNING, "swoole_set_process_name only support in CLI mode");
        RETURN_FALSE;
    }
    cli_set_process_title->internal_function.handler(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_FUNCTION(swoole_get_local_ip) {
    struct sockaddr_in *s4;
    struct ifaddrs *ipaddrs, *ifa;
    void *in_addr;
    char ip[64];

    if (getifaddrs(&ipaddrs) != 0) {
        php_swoole_sys_error(E_WARNING, "getifaddrs() failed");
        RETURN_FALSE;
    }
    array_init(return_value);
    for (ifa = ipaddrs; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *) ifa->ifa_addr;
            in_addr = &s4->sin_addr;
            break;
        case AF_INET6:
            // struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            // in_addr = &s6->sin6_addr;
            continue;
        default:
            continue;
        }
        if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, ip, sizeof(ip))) {
            php_error_docref(nullptr, E_WARNING, "%s: inet_ntop failed", ifa->ifa_name);
        } else {
            // if (ifa->ifa_addr->sa_family == AF_INET && ntohl(((struct in_addr *) in_addr)->s_addr) ==
            // INADDR_LOOPBACK)
            if (strcmp(ip, "127.0.0.1") == 0) {
                continue;
            }
            add_assoc_string(return_value, ifa->ifa_name, ip);
        }
    }
    freeifaddrs(ipaddrs);
}

static PHP_FUNCTION(swoole_get_local_mac) {
    auto add_assoc_address = [](zval *zv, const char *name, const unsigned char *addr) {
        char buf[32];
        sw_snprintf(
            SW_STRS(buf), "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        add_assoc_string(zv, name, buf);
    };
#ifdef SIOCGIFHWADDR
    struct ifconf ifc;
    struct ifreq buf[16];

    int sock;
    int i = 0, num = 0;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        php_swoole_sys_error(E_WARNING, "new socket failed");
        RETURN_FALSE;
    }
    array_init(return_value);

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t) buf;
    if (!ioctl(sock, SIOCGIFCONF, (char *) &ifc)) {
        num = ifc.ifc_len / sizeof(struct ifreq);
        while (i < num) {
            if (!(ioctl(sock, SIOCGIFHWADDR, (char *) &buf[i]))) {
                add_assoc_address(return_value, buf[i].ifr_name, (unsigned char *) buf[i].ifr_hwaddr.sa_data);
            }
            i++;
        }
    }
    close(sock);
#else
#ifdef LLADDR
    ifaddrs *ifas, *ifa;
    if (getifaddrs(&ifas) == 0) {
        array_init(return_value);
        for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr->sa_family == AF_LINK) && ifa->ifa_addr) {
                add_assoc_address(
                    return_value, ifa->ifa_name, (unsigned char *) (LLADDR((struct sockaddr_dl *) ifa->ifa_addr)));
            }
        }
        freeifaddrs(ifas);
    }
#else
    php_error_docref(nullptr, E_WARNING, "swoole_get_local_mac is not supported");
    RETURN_FALSE;
#endif
#endif
}

static PHP_FUNCTION(swoole_internal_call_user_shutdown_begin) {
    if (SWOOLE_G(req_status) == PHP_SWOOLE_RINIT_END) {
        SWOOLE_G(req_status) = PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN;
        RETURN_TRUE;
    } else {
        php_error_docref(nullptr, E_WARNING, "can not call this function in user level");
        RETURN_FALSE;
    }
}

static PHP_FUNCTION(swoole_substr_unserialize) {
    zend_long offset, length = 0;
    char *buf = NULL;
    size_t buf_len;
    zval *options = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 4)
    Z_PARAM_STRING(buf, buf_len)
    Z_PARAM_LONG(offset)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(length)
    Z_PARAM_ARRAY(options)
    ZEND_PARSE_PARAMETERS_END();

    if (buf_len == 0) {
        RETURN_FALSE;
    }
    if (offset < 0) {
        offset = buf_len + offset;
        if (offset < 0) {
            RETURN_FALSE;
        }
    }
    if ((zend_long) buf_len <= offset) {
        RETURN_FALSE;
    }
    if (length <= 0 || length > (zend_long)(buf_len - offset)) {
        length = buf_len - offset;
    }
    zend::unserialize(return_value, buf + offset, length, options ? Z_ARRVAL_P(options) : NULL);
}

static PHP_FUNCTION(swoole_substr_json_decode) {
    zend_long offset, length = 0;
    char *str;
    size_t str_len;
    zend_bool assoc = 0; /* return JS objects as PHP objects by default */
    zend_bool assoc_null = 1;
    zend_long depth = PHP_JSON_PARSER_DEFAULT_DEPTH;
    zend_long options = 0;

    ZEND_PARSE_PARAMETERS_START(2, 6)
    Z_PARAM_STRING(str, str_len)
    Z_PARAM_LONG(offset)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(length)
    Z_PARAM_BOOL_EX(assoc, assoc_null, 1, 0)
    Z_PARAM_LONG(depth)
    Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();

    if (str_len == 0) {
        php_error_docref(nullptr, E_WARNING, "Non-empty string required");
        RETURN_NULL();
    }
    if (offset < 0) {
        offset = str_len + offset;
        if (offset < 0) {
            php_error_docref(nullptr, E_WARNING, "Offset must be not less than the negative length of the string");
            RETURN_NULL();
        }
    }
    if ((zend_long) str_len <= offset) {
        php_error_docref(nullptr, E_WARNING, "Offset must be less than the length of the string");
        RETURN_NULL();
    }
    if (length <= 0 || length > (zend_long)(str_len - offset)) {
        length = str_len - offset;
    }
    /* For BC reasons, the bool $assoc overrides the long $options bit for PHP_JSON_OBJECT_AS_ARRAY */
    if (!assoc_null) {
        if (assoc) {
            options |= PHP_JSON_OBJECT_AS_ARRAY;
        } else {
            options &= ~PHP_JSON_OBJECT_AS_ARRAY;
        }
    }
    zend::json_decode(return_value, str + offset, length, options, depth);
}

/**
 * The implicit functions are intended solely for internal testing and will not be documented.
 * These functions are unsafe, do not use if you are not an internal developer.
 */
static PHP_FUNCTION(swoole_implicit_fn) {
    char *fn;
    size_t l_fn;
    zval *zargs = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(fn, l_fn)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(zargs)
    ZEND_PARSE_PARAMETERS_END();

    if (SW_STRCASEEQ(fn, l_fn, "fatal_error")) {
        swoole_fatal_error(SW_ERROR_FOR_TEST, "test");
        php_printf("never be executed here\n");
    } else if (SW_STRCASEEQ(fn, l_fn, "bailout")) {
        sw_php_exit(zargs ? zval_get_long(zargs) : 95);
    } else if (SW_STRCASEEQ(fn, l_fn, "abort")) {
        abort();
    } else if (SW_STRCASEEQ(fn, l_fn, "refcount")) {
        RETURN_LONG(zval_refcount_p(zargs));
    } else if (SW_STRCASEEQ(fn, l_fn, "func_handler")) {
        auto fn = zval_get_string(zargs);
        zend_function *zf = (zend_function *) zend_hash_find_ptr(EG(function_table), fn);
        zend_string_release(fn);
        if (zf == nullptr) {
            RETURN_FALSE;
        }
        printf("zif_handler=%p\n", zf->internal_function.handler);
    } else {
        zend_throw_exception_ex(swoole_exception_ce, SW_ERROR_INVALID_PARAMS, "unknown fn '%s'", fn);
    }
}
