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

#ifndef PHP_SWOOLE_PRIVATE_H
#define PHP_SWOOLE_PRIVATE_H

// C++ build format macros must defined earlier
#ifdef __cplusplus
#define __STDC_FORMAT_MACROS
#endif

#include "php_swoole.h"

#define SW_HAVE_COUNTABLE 1

#include "swoole_c_api.h"
#include "swoole_api.h"
#include "swoole_async.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

BEGIN_EXTERN_C()
#include <ext/date/php_date.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>
#include <ext/standard/php_array.h>
#include <ext/standard/php_var.h>
#include <ext/standard/basic_functions.h>
#include <ext/standard/php_http.h>

#define PHP_SWOOLE_VERSION SWOOLE_VERSION
#define PHP_SWOOLE_CLIENT_USE_POLL

extern PHPAPI int php_array_merge(zend_array *dest, zend_array *src);

#ifdef PHP_WIN32
#define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define PHP_SWOOLE_API __attribute__((visibility("default")))
#else
#define PHP_SWOOLE_API
#endif

#define SW_CHECK_RETURN(s)                                                                                             \
    if (s < 0) {                                                                                                       \
        RETURN_FALSE;                                                                                                  \
    } else {                                                                                                           \
        RETURN_TRUE;                                                                                                   \
    }

#define SW_LOCK_CHECK_RETURN(s)                                                                                        \
    zend_long ___tmp_return_value = s;                                                                                 \
    if (___tmp_return_value == 0) {                                                                                    \
        RETURN_TRUE;                                                                                                   \
    } else {                                                                                                           \
        zend_update_property_long(NULL, SW_Z8_OBJ_P(ZEND_THIS), SW_STRL("errCode"), ___tmp_return_value);              \
        RETURN_FALSE;                                                                                                  \
    }

#define php_swoole_fatal_error(level, fmt_str, ...)                                                                    \
    php_error_docref(NULL, level, (const char *) (fmt_str), ##__VA_ARGS__)

#define php_swoole_error(level, fmt_str, ...)                                                                          \
    if (SWOOLE_G(display_errors) || level == E_ERROR) php_swoole_fatal_error(level, fmt_str, ##__VA_ARGS__)

#define php_swoole_sys_error(level, fmt_str, ...)                                                                      \
    php_swoole_error(level, fmt_str ", Error: %s[%d]", ##__VA_ARGS__, strerror(errno), errno)

#ifdef SW_USE_CARES
#ifndef HAVE_CARES
#error "Enable c-ares support, require c-ares library"
#endif
#endif

#ifdef SW_SOCKETS
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#endif

#if PHP_VERSION_ID < 70200
#error "require PHP version 7.2 or later"
#endif

#if defined(ZTS) && defined(SW_USE_THREAD_CONTEXT)
#error "thread context cannot be used with ZTS"
#endif

//--------------------------------------------------------
#define SW_MAX_FIND_COUNT 100  // for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE 65535
//--------------------------------------------------------
enum php_swoole_client_callback_type {
    SW_CLIENT_CB_onConnect = 1,
    SW_CLIENT_CB_onReceive,
    SW_CLIENT_CB_onClose,
    SW_CLIENT_CB_onError,
    SW_CLIENT_CB_onBufferFull,
    SW_CLIENT_CB_onBufferEmpty,
#ifdef SW_USE_OPENSSL
    SW_CLIENT_CB_onSSLReady,
#endif
};
//---------------------------------------------------------
#define SW_FLAG_KEEP (1u << 12)
#define SW_FLAG_ASYNC (1u << 10)
#define SW_FLAG_SYNC (1u << 11)
//---------------------------------------------------------
enum php_swoole_fd_type {
    PHP_SWOOLE_FD_STREAM_CLIENT = SW_FD_STREAM_CLIENT,
    PHP_SWOOLE_FD_DGRAM_CLIENT,
    PHP_SWOOLE_FD_MYSQL,
    PHP_SWOOLE_FD_REDIS,
    PHP_SWOOLE_FD_HTTPCLIENT,
    PHP_SWOOLE_FD_PROCESS_STREAM,
    PHP_SWOOLE_FD_MYSQL_CORO,
    PHP_SWOOLE_FD_REDIS_CORO,
    PHP_SWOOLE_FD_POSTGRESQL,
    PHP_SWOOLE_FD_SOCKET,
    PHP_SWOOLE_FD_CO_CURL,
};
//---------------------------------------------------------
enum php_swoole_req_status {
    PHP_SWOOLE_RINIT_BEGIN,
    PHP_SWOOLE_RINIT_END,
    PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN,
    PHP_SWOOLE_RSHUTDOWN_BEGIN,
    PHP_SWOOLE_RSHUTDOWN_END,
};
//---------------------------------------------------------
enum php_swoole_hook_type {
    PHP_SWOOLE_HOOK_BEFORE_ENABLE_HOOK = SW_GLOBAL_HOOK_USER,
    PHP_SWOOLE_HOOK_AFTER_ENABLE_HOOK,
};
//---------------------------------------------------------

static sw_inline enum swSocketType php_swoole_socktype(long type) {
    return (enum swSocketType)(type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL));
}

extern zend_class_entry *swoole_event_ce;
extern zend_class_entry *swoole_timer_ce;
extern zend_class_entry *swoole_socket_coro_ce;
extern zend_class_entry *swoole_client_ce;
extern zend_class_entry *swoole_server_ce;
extern zend_object_handlers swoole_server_handlers;
extern zend_class_entry *swoole_redis_server_ce;
extern zend_object_handlers swoole_redis_server_handlers;
extern zend_class_entry *swoole_connection_iterator_ce;
extern zend_class_entry *swoole_process_ce;
extern zend_class_entry *swoole_http_server_ce;
extern zend_object_handlers swoole_http_server_handlers;
extern zend_class_entry *swoole_websocket_server_ce;
extern zend_class_entry *swoole_websocket_frame_ce;
extern zend_class_entry *swoole_server_port_ce;
extern zend_class_entry *swoole_exception_ce;
extern zend_object_handlers swoole_exception_handlers;
extern zend_class_entry *swoole_error_ce;

PHP_FUNCTION(swoole_clear_dns_cache);
PHP_FUNCTION(swoole_last_error);
PHP_FUNCTION(swoole_set_process_name);
//---------------------------------------------------------
//                  Coroutine API
//---------------------------------------------------------
PHP_FUNCTION(swoole_coroutine_create);
PHP_FUNCTION(swoole_coroutine_exec);
PHP_FUNCTION(swoole_coroutine_gethostbyname);
PHP_FUNCTION(swoole_coroutine_defer);
PHP_FUNCTION(swoole_coroutine_socketpair);
PHP_FUNCTION(swoole_test_kernel_coroutine);  // for tests
//---------------------------------------------------------
//                  event
//---------------------------------------------------------
PHP_FUNCTION(swoole_client_select);
//---------------------------------------------------------
//                  async[coro]
//---------------------------------------------------------
PHP_FUNCTION(swoole_async_set);
PHP_FUNCTION(swoole_async_dns_lookup_coro);
//---------------------------------------------------------
//                  error
//---------------------------------------------------------
#define SW_STRERROR_SYSTEM 0
#define SW_STRERROR_GAI 1
#define SW_STRERROR_DNS 2
#define SW_STRERROR_SWOOLE 9

/**
 * MINIT <Sort by dependency>
 * ==============================================================
 */
void php_swoole_event_minit(int module_number);
// base
void php_swoole_atomic_minit(int module_number);
void php_swoole_lock_minit(int module_number);
void php_swoole_process_minit(int module_number);
void php_swoole_process_pool_minit(int module_number);
void php_swoole_table_minit(int module_number);
void php_swoole_timer_minit(int module_number);
// coroutine
void php_swoole_coroutine_minit(int module_number);
void php_swoole_coroutine_system_minit(int module_number);
void php_swoole_coroutine_scheduler_minit(int module_number);
void php_swoole_channel_coro_minit(int module_number);
void php_swoole_runtime_minit(int module_number);
// client
void php_swoole_socket_coro_minit(int module_number);
void php_swoole_client_minit(int module_number);
void php_swoole_client_coro_minit(int module_number);
void php_swoole_http_client_coro_minit(int module_number);
void php_swoole_mysql_coro_minit(int module_number);
void php_swoole_redis_coro_minit(int module_number);
#ifdef SW_USE_HTTP2
void php_swoole_http2_client_coro_minit(int module_number);
#endif
// server
void php_swoole_server_minit(int module_number);
void php_swoole_server_port_minit(int module_number);
void php_swoole_http_request_minit(int module_number);
void php_swoole_http_response_minit(int module_number);
void php_swoole_http_server_minit(int module_number);
void php_swoole_http_server_coro_minit(int module_number);
void php_swoole_websocket_server_minit(int module_number);
void php_swoole_redis_server_minit(int module_number);

/**
 * RINIT
 * ==============================================================
 */
void php_swoole_coroutine_rinit();
void php_swoole_runtime_rinit();

/**
 * RSHUTDOWN
 * ==============================================================
 */
void php_swoole_async_coro_rshutdown();
void php_swoole_redis_server_rshutdown();
void php_swoole_coroutine_rshutdown();
void php_swoole_runtime_rshutdown();
void php_swoole_server_rshutdown();

int php_swoole_reactor_init();
void php_swoole_set_global_option(zend_array *vht);
void php_swoole_set_coroutine_option(zend_array *vht);
void php_swoole_set_aio_option(zend_array *vht);

// shutdown
void php_swoole_register_shutdown_function(const char *function);
void php_swoole_register_shutdown_function_prepend(const char *function);

// event
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_event_exit();

/**
 * MSHUTDOWN
 * ==============================================================
 */
void php_swoole_runtime_mshutdown();

static sw_inline zend_bool php_swoole_websocket_frame_is_object(zval *zdata) {
    return Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_websocket_frame_ce);
}

static sw_inline size_t php_swoole_get_send_data(zval *zdata, char **str) {
    convert_to_string(zdata);
    *str = Z_STRVAL_P(zdata);
    return Z_STRLEN_P(zdata);
}

int php_swoole_convert_to_fd(zval *zsocket);
int php_swoole_convert_to_fd_ex(zval *zsocket, int *async);

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *php_swoole_convert_to_socket(int sock);
#endif

zend_bool php_swoole_signal_isset_handler(int signo);

// Fixed in php-7.2.3RC1 (https://github.com/php/php-src/commit/e88e83d3e5c33fcd76f08b23e1a2e4e8dc98ce41)
#if PHP_MAJOR_VERSION == 7 && ((PHP_MINOR_VERSION == 2 && PHP_RELEASE_VERSION < 3))
// See https://github.com/php/php-src/commit/0495bf5650995cd8f18d6a9909eb4c5dcefde669
// Then https://github.com/php/php-src/commit/2dcfd8d16f5fa69582015cbd882aff833075a34c
// See https://github.com/php/php-src/commit/52db03b3e52bfc886896925d050af79bc4dc1ba3
#if PHP_MINOR_VERSION == 2
#define SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR                                                                           \
    zend_wrong_parameters_count_error(_flags &ZEND_PARSE_PARAMS_THROW, _num_args, _min_num_args, _max_num_args)
#else
#define SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR zend_wrong_parameters_count_error(_num_args, _min_num_args, _max_num_args)
#endif

#undef ZEND_PARSE_PARAMETERS_START_EX

#define ZEND_PARSE_PARAMETERS_START_EX(flags, min_num_args, max_num_args)                                              \
    do {                                                                                                               \
        const int _flags = (flags);                                                                                    \
        int _min_num_args = (min_num_args);                                                                            \
        int _max_num_args = (max_num_args);                                                                            \
        int _num_args = EX_NUM_ARGS();                                                                                 \
        int _i;                                                                                                        \
        zval *_real_arg, *_arg = NULL;                                                                                 \
        zend_expected_type _expected_type = Z_EXPECTED_LONG;                                                           \
        char *_error = NULL;                                                                                           \
        zend_bool _dummy;                                                                                              \
        zend_bool _optional = 0;                                                                                       \
        int error_code = ZPP_ERROR_OK;                                                                                 \
        ((void) _i);                                                                                                   \
        ((void) _real_arg);                                                                                            \
        ((void) _arg);                                                                                                 \
        ((void) _expected_type);                                                                                       \
        ((void) _error);                                                                                               \
        ((void) _dummy);                                                                                               \
        ((void) _optional);                                                                                            \
                                                                                                                       \
        do {                                                                                                           \
            if (UNEXPECTED(_num_args < _min_num_args) ||                                                               \
                (UNEXPECTED(_num_args > _max_num_args) && EXPECTED(_max_num_args >= 0))) {                             \
                if (!(_flags & ZEND_PARSE_PARAMS_QUIET)) {                                                             \
                    SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR;                                                              \
                }                                                                                                      \
                error_code = ZPP_ERROR_FAILURE;                                                                        \
                break;                                                                                                 \
            }                                                                                                          \
            _i = 0;                                                                                                    \
            _real_arg = ZEND_CALL_ARG(execute_data, 0);
#endif

/* PHP 7.3 compatibility macro {{{*/

#ifndef GC_ADDREF
#define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
#define GC_DELREF(ref) --GC_REFCOUNT(ref)
#endif

#ifndef ZEND_CLOSURE_OBJECT
#define ZEND_CLOSURE_OBJECT(func) (zend_object *) func->op_array.prototype
#endif

/* PHP 7.4 compatibility macro {{{*/
#ifndef ZEND_COMPILE_EXTENDED_STMT
#define ZEND_COMPILE_EXTENDED_STMT ZEND_COMPILE_EXTENDED_INFO
#endif

#ifndef ZVAL_EMPTY_ARRAY
#define ZVAL_EMPTY_ARRAY(zval) (array_init((zval)))
#endif
#ifndef RETVAL_EMPTY_ARRAY
#define RETVAL_EMPTY_ARRAY() ZVAL_EMPTY_ARRAY(return_value)
#endif
#ifndef RETURN_EMPTY_ARRAY
#define RETURN_EMPTY_ARRAY()                                                                                           \
    do {                                                                                                               \
        RETVAL_EMPTY_ARRAY();                                                                                          \
        return;                                                                                                        \
    } while (0)
#endif

#ifndef ZEND_THIS
#define ZEND_THIS (&EX(This))
#endif

#ifndef ZEND_THIS_OBJECT
#define ZEND_THIS_OBJECT Z_OBJ_P(ZEND_THIS)
#endif

#ifndef E_FATAL_ERRORS
#define E_FATAL_ERRORS (E_ERROR | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR | E_PARSE)
#endif
/*}}}*/

/* PHP 8 compatibility macro {{{*/
#if PHP_VERSION_ID < 80000
#define sw_zend7_object zval
#define SW_Z7_OBJ_P(object) Z_OBJ_P(object)
#define SW_Z8_OBJ_P(zobj) zobj
#else
#define sw_zend7_object zend_object
#define SW_Z7_OBJ_P(object) object
#define SW_Z8_OBJ_P(zobj) Z_OBJ_P(zobj)
#endif
/*}}}*/

#if PHP_VERSION_ID < 70400
typedef size_t php_stream_size_t;
#else
typedef ssize_t php_stream_size_t;
#endif

#if PHP_VERSION_ID < 80000
#define ZEND_ERROR_CB_LAST_ARG_D const char *format, va_list args
#define ZEND_ERROR_CB_LAST_ARG_RELAY format, args
#else
#define ZEND_ERROR_CB_LAST_ARG_D zend_string *message
#define ZEND_ERROR_CB_LAST_ARG_RELAY message
#endif

#if PHP_VERSION_ID < 80100
typedef const char error_filename_t;
#else
typedef zend_string error_filename_t;
#endif

#if PHP_VERSION_ID < 80200
# define zend_atomic_bool zend_bool
# define zend_atomic_bool_store(atomic, desired) (*atomic = desired)
#endif

/* PHP 7 wrapper functions / macros */

//----------------------------------Zval API------------------------------------

// Deprecated: do not use it anymore
// do not use sw_copy_to_stack(return_value, foo);
#define sw_copy_to_stack(ptr, val)                                                                                     \
    do {                                                                                                               \
        (val) = *(zval *) (ptr);                                                                                       \
        (ptr) = &(val);                                                                                                \
    } while (0)

#if PHP_VERSION_ID < 80000
#define SW_ZVAL_SOCKET(return_value, result)                                                                           \
    ZVAL_RES(return_value, zend_register_resource((void *) (result), php_sockets_le_socket()))
#else
#define SW_ZVAL_SOCKET(return_value, result) ZVAL_OBJ(return_value, &result->std)
#endif

#if PHP_VERSION_ID < 80000
#define SW_Z_SOCKET_P(zsocket) (php_socket *) zend_fetch_resource_ex(zsocket, nullptr, php_sockets_le_socket())
#else
#define SW_Z_SOCKET_P(zsocket) Z_SOCKET_P(zsocket)
#endif

#ifndef ZVAL_IS_BOOL
static sw_inline zend_bool ZVAL_IS_BOOL(zval *v) {
    return Z_TYPE_P(v) == IS_TRUE || Z_TYPE_P(v) == IS_FALSE;
}
#endif

#ifndef ZVAL_IS_TRUE
static sw_inline zend_bool ZVAL_IS_TRUE(zval *v) {
    return Z_TYPE_P(v) == IS_TRUE;
}
#endif

#ifndef ZVAL_IS_UNDEF
static sw_inline zend_bool ZVAL_IS_UNDEF(zval *v) {
    return Z_TYPE_P(v) == IS_UNDEF;
}
#endif

#ifndef ZVAL_IS_FALSE
static sw_inline zend_bool ZVAL_IS_FALSE(zval *v) {
    return Z_TYPE_P(v) == IS_FALSE;
}
#endif

#ifndef ZVAL_IS_LONG
static sw_inline zend_bool ZVAL_IS_LONG(zval *v) {
    return Z_TYPE_P(v) == IS_LONG;
}
#endif

#ifndef ZVAL_IS_STRING
static sw_inline zend_bool ZVAL_IS_STRING(zval *v) {
    return Z_TYPE_P(v) == IS_STRING;
}
#endif

#ifndef Z_BVAL_P
static sw_inline zend_bool Z_BVAL_P(zval *v) {
    return Z_TYPE_P(v) == IS_TRUE;
}
#endif

#ifndef ZVAL_IS_ARRAY
static sw_inline zend_bool ZVAL_IS_ARRAY(zval *v) {
    return Z_TYPE_P(v) == IS_ARRAY;
}
#endif

#ifndef ZVAL_IS_OBJECT
static sw_inline zend_bool ZVAL_IS_OBJECT(zval *v) {
    return Z_TYPE_P(v) == IS_OBJECT;
}
#endif

#ifndef IS_MIXED
#define IS_MIXED 0
#endif

static sw_inline zval *sw_malloc_zval() {
    return (zval *) emalloc(sizeof(zval));
}

static sw_inline zval *sw_zval_dup(zval *val) {
    zval *dup = sw_malloc_zval();
    memcpy(dup, val, sizeof(zval));
    return dup;
}

static sw_inline void sw_zval_free(zval *val) {
    zval_ptr_dtor(val);
    efree(val);
}

//----------------------------------Constant API------------------------------------

#define SW_REGISTER_NULL_CONSTANT(name) REGISTER_NULL_CONSTANT(name, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_BOOL_CONSTANT(name, value) REGISTER_BOOL_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_LONG_CONSTANT(name, value) REGISTER_LONG_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_DOUBLE_CONSTANT(name, value) REGISTER_DOUBLE_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_STRING_CONSTANT(name, value)                                                                       \
    REGISTER_STRING_CONSTANT(name, (char *) value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_STRINGL_CONSTANT(name, value)                                                                      \
    REGISTER_STRINGL_CONSTANT(name, (char *) value, CONST_CS | CONST_PERSISTENT)

//----------------------------------Number API-----------------------------------

#define sw_php_math_round(value, places, mode) _php_math_round(value, places, mode)

//----------------------------------String API-----------------------------------

#define SW_PHP_OB_START(zoutput)                                                                                       \
    zval zoutput;                                                                                                      \
    do {                                                                                                               \
        php_output_start_user(NULL, 0, PHP_OUTPUT_HANDLER_STDFLAGS);
#define SW_PHP_OB_END()                                                                                                \
    php_output_get_contents(&zoutput);                                                                                 \
    php_output_discard();                                                                                              \
    }                                                                                                                  \
    while (0)

static sw_inline zend_string *sw_zend_string_recycle(zend_string *s, size_t alloc_len, size_t real_len) {
    SW_ASSERT(!ZSTR_IS_INTERNED(s));
    if (UNEXPECTED(alloc_len != real_len)) {
        if (alloc_len > swoole_pagesize() && alloc_len > real_len * 2) {
            s = zend_string_realloc(s, real_len, 0);
        } else {
            ZSTR_LEN(s) = real_len;
        }
    }
    ZSTR_VAL(s)[real_len] = '\0';
    return s;
}

//----------------------------------Array API------------------------------------

#define php_swoole_array_length(zarray) zend_hash_num_elements(Z_ARRVAL_P(zarray))
#define php_swoole_array_get_value(ht, str, v) ((v = zend_hash_str_find(ht, str, sizeof(str) - 1)) && !ZVAL_IS_NULL(v))
#define php_swoole_array_get_value_ex(ht, str, v) ((v = zend_hash_str_find(ht, str, strlen(str))) && !ZVAL_IS_NULL(v))

static sw_inline int php_swoole_array_length_safe(zval *zarray) {
    if (zarray && ZVAL_IS_ARRAY(zarray)) {
        return php_swoole_array_length(zarray);
    } else {
        return 0;
    }
}

void php_swoole_sha1(const char *str, int _len, uchar *digest);
void php_swoole_sha256(const char *str, int _len, uchar *digest);

#define SW_HASHTABLE_FOREACH_START(ht, _val)                                                                           \
    ZEND_HASH_FOREACH_VAL(ht, _val);                                                                                   \
    {
#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, _val)                                                          \
    zend_string *_foreach_key;                                                                                         \
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, _foreach_key, _val);                                                             \
    if (!_foreach_key) {                                                                                               \
        k = NULL;                                                                                                      \
        klen = 0;                                                                                                      \
        ktype = 0;                                                                                                     \
    } else {                                                                                                           \
        k = ZSTR_VAL(_foreach_key), klen = ZSTR_LEN(_foreach_key);                                                     \
        ktype = 1;                                                                                                     \
    }                                                                                                                  \
    {
#define SW_HASHTABLE_FOREACH_END()                                                                                     \
    }                                                                                                                  \
    ZEND_HASH_FOREACH_END();

static sw_inline void add_assoc_ulong_safe_ex(zval *arg, const char *key, size_t key_len, zend_ulong value) {
    if (sw_likely(value <= ZEND_LONG_MAX)) {
        add_assoc_long_ex(arg, key, key_len, value);
    } else {
        char buf[MAX_LENGTH_OF_LONG + 1];
        size_t len = sw_snprintf(buf, sizeof(buf), ZEND_ULONG_FMT, value);
        add_assoc_stringl_ex(arg, key, key_len, buf, len);
    }
}

static sw_inline void add_assoc_ulong_safe(zval *arg, const char *key, zend_ulong value) {
    add_assoc_ulong_safe_ex(arg, key, strlen(key), value);
}

//----------------------------------Class API------------------------------------

#define SW_Z_OBJCE_NAME_VAL_P(zobject) ZSTR_VAL(Z_OBJCE_P(zobject)->name)

/* PHP 7 class declaration macros */

#define SW_INIT_CLASS_ENTRY_BASE(module, namespace_name, snake_name, short_name, methods, parent_ce)                   \
    do {                                                                                                               \
        zend_class_entry _##module##_ce = {};                                                                          \
        INIT_CLASS_ENTRY(_##module##_ce, namespace_name, methods);                                                     \
        module##_ce = zend_register_internal_class_ex(&_##module##_ce, parent_ce);                                     \
        if (snake_name) SW_CLASS_ALIAS(snake_name, module);                                                            \
        if (short_name) SW_CLASS_ALIAS_SHORT_NAME(short_name, module);                                                 \
    } while (0)

#define SW_INIT_CLASS_ENTRY(module, namespace_name, snake_name, short_name, methods)                                   \
    SW_INIT_CLASS_ENTRY_BASE(module, namespace_name, snake_name, short_name, methods, NULL);                           \
    memcpy(&module##_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers))

#define SW_INIT_CLASS_ENTRY_EX(module, namespace_name, snake_name, short_name, methods, parent_module)                 \
    SW_INIT_CLASS_ENTRY_BASE(module, namespace_name, snake_name, short_name, methods, parent_module##_ce);             \
    memcpy(&module##_handlers, &parent_module##_handlers, sizeof(zend_object_handlers))

#define SW_INIT_CLASS_ENTRY_EX2(                                                                                       \
    module, namespace_name, snake_name, short_name, methods, parent_module_ce, parent_module_handlers)                 \
    SW_INIT_CLASS_ENTRY_BASE(module, namespace_name, snake_name, short_name, methods, parent_module_ce);               \
    memcpy(&module##_handlers, parent_module_handlers, sizeof(zend_object_handlers))

// Data Object: no methods, no parent
#define SW_INIT_CLASS_ENTRY_DATA_OBJECT(module, namespace_name)                                                        \
    SW_INIT_CLASS_ENTRY_BASE(module, namespace_name, NULL, NULL, NULL, NULL);                                          \
    memcpy(&module##_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers))

#define SW_CLASS_ALIAS(name, module)                                                                                   \
    do {                                                                                                               \
        if (name) {                                                                                                    \
            sw_zend_register_class_alias(ZEND_STRL(name), module##_ce);                                                \
        }                                                                                                              \
    } while (0)

#define SW_CLASS_ALIAS_SHORT_NAME(short_name, module)                                                                  \
    do {                                                                                                               \
        if (SWOOLE_G(use_shortname)) {                                                                                 \
            SW_CLASS_ALIAS(short_name, module);                                                                        \
        }                                                                                                              \
    } while (0)

#if PHP_VERSION_ID < 80100
#define SW_SET_CLASS_NOT_SERIALIZABLE(module)                                                                          \
    module##_ce->serialize = zend_class_serialize_deny;                                                                \
    module##_ce->unserialize = zend_class_unserialize_deny;
#else
#define SW_SET_CLASS_NOT_SERIALIZABLE(module) module##_ce->ce_flags |= ZEND_ACC_NOT_SERIALIZABLE;
#endif

#define sw_zend_class_clone_deny NULL
#define SW_SET_CLASS_CLONEABLE(module, _clone_obj) module##_handlers.clone_obj = _clone_obj

#define SW_SET_CLASS_UNSET_PROPERTY_HANDLER(module, _unset_property) module##_handlers.unset_property = _unset_property

#define SW_SET_CLASS_CREATE(module, _create_object) module##_ce->create_object = _create_object

#define SW_SET_CLASS_DTOR(module, _dtor_obj) module##_handlers.dtor_obj = _dtor_obj

#define SW_SET_CLASS_FREE(module, _free_obj) module##_handlers.free_obj = _free_obj

#define SW_SET_CLASS_CREATE_AND_FREE(module, _create_object, _free_obj)                                                \
    SW_SET_CLASS_CREATE(module, _create_object);                                                                       \
    SW_SET_CLASS_FREE(module, _free_obj)

#define SW_SET_CLASS_CUSTOM_OBJECT(module, _create_object, _free_obj, _struct, _std)                                   \
    SW_SET_CLASS_CREATE_AND_FREE(module, _create_object, _free_obj);                                                   \
    module##_handlers.offset = XtOffsetOf(_struct, _std)

#define SW_PREVENT_USER_DESTRUCT()                                                                                     \
    do {                                                                                                               \
        if (sw_unlikely(!(GC_FLAGS(Z_OBJ_P(ZEND_THIS)) & IS_OBJ_DESTRUCTOR_CALLED))) {                                 \
            RETURN_NULL();                                                                                             \
        }                                                                                                              \
    } while (0)

#define SW_FUNCTION_ALIAS(origin_function_table, origin, alias_function_table, alias)                                  \
    sw_zend_register_function_alias(origin_function_table, ZEND_STRL(origin), alias_function_table, ZEND_STRL(alias))

static sw_inline int sw_zend_register_function_alias(zend_array *origin_function_table,
                                                     const char *origin,
                                                     size_t origin_length,
                                                     zend_array *alias_function_table,
                                                     const char *alias,
                                                     size_t alias_length) {
    zend_string *lowercase_origin = zend_string_alloc(origin_length, 0);
    zend_str_tolower_copy(ZSTR_VAL(lowercase_origin), origin, origin_length);
    zend_function *origin_function = (zend_function *) zend_hash_find_ptr(origin_function_table, lowercase_origin);
    zend_string_release(lowercase_origin);
    if (UNEXPECTED(!origin_function)) {
        return FAILURE;
    }
    SW_ASSERT(origin_function->common.type == ZEND_INTERNAL_FUNCTION);
    char *_alias = (char *) emalloc(alias_length + 1);
    ((char *) memcpy(_alias, alias, alias_length))[alias_length] = '\0';
    zend_function_entry zfe[] = {{_alias,
                                  origin_function->internal_function.handler,
                                  ((zend_internal_arg_info *) origin_function->common.arg_info) - 1,
                                  origin_function->common.num_args,
                                  0},
                                 PHP_FE_END};
    int ret =
        zend_register_functions(origin_function->common.scope, zfe, alias_function_table, origin_function->common.type);
    efree(_alias);
    return ret;
}

static sw_inline int sw_zend_register_class_alias(const char *name, size_t name_len, zend_class_entry *ce) {
    zend_string *_name;
    if (name[0] == '\\') {
        _name = zend_string_init(name, name_len, 1);
        zend_str_tolower_copy(ZSTR_VAL(_name), name + 1, name_len - 1);
    } else {
        _name = zend_string_init(name, name_len, 1);
        zend_str_tolower_copy(ZSTR_VAL(_name), name, name_len);
    }

    zend_string *_interned_name = zend_new_interned_string(_name);

#if PHP_VERSION_ID >= 70300
    return zend_register_class_alias_ex(ZSTR_VAL(_interned_name), ZSTR_LEN(_interned_name), ce, 1);
#else
    return zend_register_class_alias_ex(ZSTR_VAL(_interned_name), ZSTR_LEN(_interned_name), ce);
#endif
}

#if PHP_VERSION_ID < 70300
/* Allocates object type and zeros it, but not the properties.
 * Properties MUST be initialized using object_properties_init(). */
static zend_always_inline void *zend_object_alloc(size_t obj_size, zend_class_entry *ce) {
    void *obj = emalloc(obj_size + zend_object_properties_size(ce));
    /* Subtraction of sizeof(zval) is necessary, because zend_object_properties_size() may be
     * -sizeof(zval), if the object has no properties. */
    memset(obj, 0, obj_size - sizeof(zval));
    return obj;
}
#endif

static sw_inline zend_object *sw_zend_create_object(zend_class_entry *ce, zend_object_handlers *handlers) {
    zend_object *object = (zend_object *) zend_object_alloc(sizeof(zend_object), ce);
    zend_object_std_init(object, ce);
    object_properties_init(object, ce);
    object->handlers = handlers;
    return object;
}

static sw_inline zend_object *sw_zend_create_object_deny(zend_class_entry *ce) {
    zend_object *object;
    object = zend_objects_new(ce);
    /* Initialize default properties */
    if (EXPECTED(ce->default_properties_count != 0)) {
        zval *p = object->properties_table;
        zval *end = p + ce->default_properties_count;
        do {
            ZVAL_UNDEF(p);
            p++;
        } while (p != end);
    }
    zend_throw_error(NULL, "The object of %s can not be created for security reasons", ZSTR_VAL(ce->name));
    return object;
}

#if PHP_VERSION_ID < 80000
static sw_inline void sw_zend_class_unset_property_deny(zval *zobject, zval *zmember, void **cache_slot) {
    zend_class_entry *ce = Z_OBJCE_P(zobject);
    while (ce->parent) {
        ce = ce->parent;
    }
    SW_ASSERT(ce->type == ZEND_INTERNAL_CLASS);
    if (EXPECTED(zend_hash_find(&ce->properties_info, Z_STR_P(zmember)))) {
        zend_throw_error(
            NULL, "Property %s of class %s cannot be unset", Z_STRVAL_P(zmember), SW_Z_OBJCE_NAME_VAL_P(zobject));
        return;
    }
    std_object_handlers.unset_property(zobject, zmember, cache_slot);
}
#else
static sw_inline void sw_zend_class_unset_property_deny(zend_object *object, zend_string *member, void **cache_slot) {
    zend_class_entry *ce = object->ce;
    while (ce->parent) {
        ce = ce->parent;
    }
    SW_ASSERT(ce->type == ZEND_INTERNAL_CLASS);
    if (EXPECTED(zend_hash_find(&ce->properties_info, member))) {
        zend_throw_error(NULL, "Property %s of class %s cannot be unset", ZSTR_VAL(member), ZSTR_VAL(object->ce->name));
        return;
    }
    std_object_handlers.unset_property(object, member, cache_slot);
}
#endif

static sw_inline zval *sw_zend_read_property(zend_class_entry *ce, zval *obj, const char *s, size_t len, int silent) {
    zval rv, *property = zend_read_property(ce, SW_Z8_OBJ_P(obj), s, len, silent, &rv);
    if (UNEXPECTED(property == &EG(uninitialized_zval))) {
        zend_update_property_null(ce, SW_Z8_OBJ_P(obj), s, len);
        return zend_read_property(ce, SW_Z8_OBJ_P(obj), s, len, silent, &rv);
    }
    return property;
}

static sw_inline void sw_zend_update_property_null_ex(zend_class_entry *scope, zval *object, zend_string *s) {
    zval tmp;

    ZVAL_NULL(&tmp);
    zend_update_property_ex(scope, SW_Z8_OBJ_P(object), s, &tmp);
}

static sw_inline zval *sw_zend_read_property_ex(zend_class_entry *ce, zval *obj, zend_string *s, int silent) {
    zval rv, *property = zend_read_property_ex(ce, SW_Z8_OBJ_P(obj), s, silent, &rv);
    if (UNEXPECTED(property == &EG(uninitialized_zval))) {
        sw_zend_update_property_null_ex(ce, obj, s);
        return zend_read_property_ex(ce, SW_Z8_OBJ_P(obj), s, silent, &rv);
    }
    return property;
}

static sw_inline zval *sw_zend_read_property_not_null(
    zend_class_entry *ce, zval *obj, const char *s, size_t len, int silent) {
    zval rv, *property = zend_read_property(ce, SW_Z8_OBJ_P(obj), s, len, silent, &rv);
    zend_uchar type = Z_TYPE_P(property);
    return (type == IS_NULL || UNEXPECTED(type == IS_UNDEF)) ? NULL : property;
}

static sw_inline zval *sw_zend_read_property_not_null_ex(zend_class_entry *ce, zval *obj, zend_string *s, int silent) {
    zval rv, *property = zend_read_property_ex(ce, SW_Z8_OBJ_P(obj), s, silent, &rv);
    zend_uchar type = Z_TYPE_P(property);
    return (type == IS_NULL || UNEXPECTED(type == IS_UNDEF)) ? NULL : property;
}

static sw_inline zval *sw_zend_update_and_read_property_array(zend_class_entry *ce, zval *obj, const char *s, size_t len) {
    zval ztmp;
    array_init(&ztmp);
    zend_update_property(ce, SW_Z8_OBJ_P(obj), s, len, &ztmp);
    zval_ptr_dtor(&ztmp);
    return zend_read_property(ce, SW_Z8_OBJ_P(obj), s, len, 1, &ztmp);
}

static sw_inline zval *sw_zend_read_and_convert_property_array(
    zend_class_entry *ce, zval *obj, const char *s, size_t len, int silent) {
    zval rv, *property = zend_read_property(ce, SW_Z8_OBJ_P(obj), s, len, silent, &rv);
    if (Z_TYPE_P(property) != IS_ARRAY) {
        // NOTICE: if user unset the property, zend_read_property will return uninitialized_zval instead of NULL pointer
        if (UNEXPECTED(property == &EG(uninitialized_zval))) {
            property = sw_zend_update_and_read_property_array(ce, obj, s, len);
        } else {
            zval_ptr_dtor(property);
            array_init(property);
        }
    }

    return property;
}

#define SW_RETURN_PROPERTY(name)                                                                                       \
    do {                                                                                                               \
        RETURN_ZVAL(sw_zend_read_property(Z_OBJCE_P(ZEND_THIS), ZEND_THIS, ZEND_STRL(name), 0), 1, 0);                 \
    } while (0)

#define RETURN_SW_STRING(buf)                                                                                          \
    do {                                                                                                               \
        RETURN_STRINGL(buf->str, buf->length);                                                                         \
    } while (0)

//----------------------------------Function API------------------------------------

/**
 * Notice (sw_zend_call_method_with_%u_params): If you don't want to check the return value, please set retval to NULL
 */
#define sw_zend_call_method_with_0_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval)                                   \
    zend_call_method_with_0_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval)

#define sw_zend_call_method_with_1_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval, v1)                               \
    zend_call_method_with_1_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval, v1)

#define sw_zend_call_method_with_2_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval, v1, v2)                           \
    zend_call_method_with_2_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval, v1, v2)

static sw_inline int sw_zend_function_max_num_args(zend_function *function) {
    // https://github.com/php/php-src/commit/2646f7bcb98dcdd322ea21701c8bb101104ea619
    // zend_function.common.num_args don't include the variadic argument anymore.
    return (function->common.fn_flags & ZEND_ACC_VARIADIC) ? UINT32_MAX : function->common.num_args;
}

// TODO: remove it after remove async modules
static sw_inline zend_bool sw_zend_is_callable(zval *callable, int check_flags, char **callable_name) {
    zend_string *name;
    zend_bool ret = zend_is_callable(callable, check_flags, &name);
    *callable_name = estrndup(ZSTR_VAL(name), ZSTR_LEN(name));
    zend_string_release(name);
    return ret;
}

static sw_inline zend_bool sw_zend_is_callable_at_frame(zval *zcallable,
                                                        zval *zobject,
                                                        zend_execute_data *frame,
                                                        uint check_flags,
                                                        char **callable_name,
                                                        size_t *callable_name_len,
                                                        zend_fcall_info_cache *fci_cache,
                                                        char **error) {
    zend_string *name;
    zend_bool ret;
#if PHP_VERSION_ID < 80000
    ret = zend_is_callable_ex(zcallable, zobject ? Z_OBJ_P(zobject) : NULL, check_flags, &name, fci_cache, error);
#else
    ret = zend_is_callable_at_frame(zcallable, zobject ? Z_OBJ_P(zobject) : NULL, frame, check_flags, fci_cache, error);
    name = zend_get_callable_name_ex(zcallable, zobject ? Z_OBJ_P(zobject) : NULL);
#endif
    if (callable_name) {
        *callable_name = estrndup(ZSTR_VAL(name), ZSTR_LEN(name));
    }
    if (callable_name_len) {
        *callable_name_len = ZSTR_LEN(name);
    }
    zend_string_release(name);
    return ret;
}

static sw_inline zend_bool sw_zend_is_callable_ex(zval *zcallable,
                                                  zval *zobject,
                                                  uint check_flags,
                                                  char **callable_name,
                                                  size_t *callable_name_len,
                                                  zend_fcall_info_cache *fci_cache,
                                                  char **error) {
    return sw_zend_is_callable_at_frame(
        zcallable, zobject, NULL, check_flags, callable_name, callable_name_len, fci_cache, error);
}

/* this API can work well when retval is NULL */
static sw_inline int sw_zend_call_function_ex(
    zval *function_name, zend_fcall_info_cache *fci_cache, uint32_t param_count, zval *params, zval *retval) {
    zend_fcall_info fci;
    zval _retval;
    int ret;

    fci.size = sizeof(fci);
    fci.object = NULL;
    if (!fci_cache || !fci_cache->function_handler) {
        if (!function_name) {
            php_swoole_fatal_error(E_WARNING, "Bad function");
            return FAILURE;
        }
        ZVAL_COPY_VALUE(&fci.function_name, function_name);
    } else {
        ZVAL_UNDEF(&fci.function_name);
    }
    fci.retval = retval ? retval : &_retval;
    fci.param_count = param_count;
    fci.params = params;
#if PHP_VERSION_ID >= 80000
    fci.named_params = NULL;
#else
    fci.no_separation = 0;
#endif

    ret = zend_call_function(&fci, fci_cache);

    if (!retval) {
        zval_ptr_dtor(&_retval);
    }
    return ret;
}

/* we must check for exception immediately if we don't have chances to go back to ZendVM (e.g event loop) */
static sw_inline int sw_zend_call_function_ex2(
    zval *function_name, zend_fcall_info_cache *fci_cache, uint32_t param_count, zval *params, zval *retval) {
    int ret = sw_zend_call_function_ex(function_name, fci_cache, param_count, params, retval);
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return ret;
}

static sw_inline int sw_zend_call_function_anyway(zend_fcall_info *fci, zend_fcall_info_cache *fci_cache) {
    zval retval;
    zend_object *exception = EG(exception);
    if (exception) {
        EG(exception) = NULL;
    }
    if (!fci->retval) {
        fci->retval = &retval;
    }
    int ret = zend_call_function(fci, fci_cache);
    if (fci->retval == &retval) {
        zval_ptr_dtor(&retval);
    }
    if (exception) {
        EG(exception) = exception;
    }
    return ret;
}

static sw_inline void sw_zend_fci_params_persist(zend_fcall_info *fci) {
    if (fci->param_count > 0) {
        uint32_t i;
        zval *params = (zval *) ecalloc(fci->param_count, sizeof(zval));
        for (i = 0; i < fci->param_count; i++) {
            ZVAL_COPY(&params[i], &fci->params[i]);
        }
        fci->params = params;
    }
}

static sw_inline void sw_zend_fci_params_discard(zend_fcall_info *fci) {
    if (fci->param_count > 0) {
        uint32_t i;
        for (i = 0; i < fci->param_count; i++) {
            zval_ptr_dtor(&fci->params[i]);
        }
        efree(fci->params);
    }
}

static sw_inline void sw_zend_fci_cache_persist(zend_fcall_info_cache *fci_cache) {
    if (fci_cache->object) {
        GC_ADDREF(fci_cache->object);
    }
    if (fci_cache->function_handler->op_array.fn_flags & ZEND_ACC_CLOSURE) {
        GC_ADDREF(ZEND_CLOSURE_OBJECT(fci_cache->function_handler));
    }
}

static sw_inline void sw_zend_fci_cache_discard(zend_fcall_info_cache *fci_cache) {
    if (fci_cache->object) {
        OBJ_RELEASE(fci_cache->object);
    }
    if (fci_cache->function_handler->op_array.fn_flags & ZEND_ACC_CLOSURE) {
        OBJ_RELEASE(ZEND_CLOSURE_OBJECT(fci_cache->function_handler));
    }
}

/* use void* to match some C callback function pointers */
static sw_inline void sw_zend_fci_cache_free(void *fci_cache) {
    sw_zend_fci_cache_discard((zend_fcall_info_cache *) fci_cache);
    efree((zend_fcall_info_cache *) fci_cache);
}

//----------------------------------Misc API------------------------------------

static sw_inline int php_swoole_check_reactor() {
    if (SWOOLE_G(req_status) == PHP_SWOOLE_RSHUTDOWN_BEGIN) {
        return -1;
    }
    if (sw_unlikely(!sw_reactor())) {
        return php_swoole_reactor_init() == SW_OK ? 1 : -1;
    } else {
        return 0;
    }
}

static sw_inline char *php_swoole_format_date(char *format, size_t format_len, time_t ts, int localtime) {
    zend_string *time = php_format_date(format, format_len, ts, localtime);
    char *return_str = estrndup(ZSTR_VAL(time), ZSTR_LEN(time));
    zend_string_release(time);
    return return_str;
}

static sw_inline char *php_swoole_url_encode(const char *value, size_t value_len, size_t *exten) {
    zend_string *str = php_url_encode(value, value_len);
    *exten = ZSTR_LEN(str);
    char *return_str = estrndup(ZSTR_VAL(str), ZSTR_LEN(str));
    zend_string_release(str);
    return return_str;
}

static sw_inline char *php_swoole_http_build_query(zval *zdata, size_t *length, smart_str *formstr) {
#if PHP_VERSION_ID < 80000
    if (php_url_encode_hash_ex(
            HASH_OF(zdata), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE) {
#else
    if (HASH_OF(zdata)) {
        php_url_encode_hash_ex(HASH_OF(zdata), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738);
    } else {
#endif
        if (formstr->s) {
            smart_str_free(formstr);
        }
        return NULL;
    }
    if (!formstr->s) {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->s->len;
    return formstr->s->val;
}

static inline const char *php_swoole_get_last_error_message() {
#if PHP_VERSION_ID >= 80000
    return PG(last_error_message) ? PG(last_error_message)->val : nullptr;
#else
    return PG(last_error_message);
#endif
}

static inline const char *php_swoole_get_last_error_file() {
#if PHP_VERSION_ID >= 80100
    return PG(last_error_file) ? PG(last_error_file)->val : "-";
#else
    return PG(last_error_file) ? PG(last_error_file) : "-";
#endif
}

END_EXTERN_C()

#endif /* PHP_SWOOLE_PRIVATE_H */
