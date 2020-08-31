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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

// C++ build format macros must defined earlier
#ifdef __cplusplus
#define __STDC_FORMAT_MACROS
#endif

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "php_streams.h"
#include "php_network.h"

#include "zend_variables.h"
#include "zend_interfaces.h"
#include "zend_closures.h"
#include "zend_exceptions.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// zend iterator interface
#if PHP_VERSION_ID < 70200
#ifdef HAVE_PCRE
#include "ext/spl/spl_iterators.h"
#define zend_ce_countable spl_ce_Countable
#define SW_HAVE_COUNTABLE 1
#endif
#else
#define SW_HAVE_COUNTABLE 1
#endif

#include "swoole.h"
#include "server.h"
#include "client.h"
#include "async.h"

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
#define PHP_SWOOLE_CHECK_CALLBACK
#define PHP_SWOOLE_CLIENT_USE_POLL

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define SW_HOST_SIZE  128

extern PHPAPI int php_array_merge(HashTable *dest, HashTable *src);

extern zend_module_entry swoole_module_entry;

#define phpext_swoole_ptr &swoole_module_entry

#ifdef PHP_WIN32
# define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
# define PHP_SWOOLE_API
#endif

#if __MACH__
#include <net/if_dl.h>
#endif

#define SW_CHECK_RETURN(s)      if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}
#define SW_LOCK_CHECK_RETURN(s) if(s==0){RETURN_TRUE;}else{zend_update_property_long(NULL,ZEND_THIS,SW_STRL("errCode"),s);RETURN_FALSE;}

#define php_swoole_fatal_error(level, fmt_str, ...) \
        php_error_docref(NULL, level, (const char *) (fmt_str), ##__VA_ARGS__)

#define php_swoole_error(level, fmt_str, ...) \
    if (SWOOLE_G(display_errors) || level == E_ERROR) \
        php_swoole_fatal_error(level, fmt_str, ##__VA_ARGS__)

#define php_swoole_sys_error(level, fmt_str, ...) \
        php_swoole_error(level, fmt_str ", Error: %s[%d]", ##__VA_ARGS__, strerror(errno), errno)

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, require openssl library"
#endif
#endif

#ifdef SW_SOCKETS
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#endif

#if PHP_VERSION_ID < 70100
#error "require PHP version 7.1 or later"
#endif

//--------------------------------------------------------
#define SW_MAX_FIND_COUNT                   100    //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE           65535
//--------------------------------------------------------
enum php_swoole_client_callback_type
{
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
//--------------------------------------------------------
enum php_swoole_server_callback_type
{
    SW_SERVER_CB_onStart,          //master
    SW_SERVER_CB_onShutdown,       //master
    SW_SERVER_CB_onWorkerStart,    //worker(event & task)
    SW_SERVER_CB_onWorkerStop,     //worker(event & task)
    SW_SERVER_CB_onTask,           //worker(task)
    SW_SERVER_CB_onFinish,         //worker(event & task)
    SW_SERVER_CB_onWorkerExit,     //worker(event)
    SW_SERVER_CB_onWorkerError,    //manager
    SW_SERVER_CB_onManagerStart,   //manager
    SW_SERVER_CB_onManagerStop,    //manager
    SW_SERVER_CB_onPipeMessage,    //worker(event & task)
};
//--------------------------------------------------------
enum php_swoole_server_port_callback_type
{
    SW_SERVER_CB_onConnect,        //worker(event)
    SW_SERVER_CB_onReceive,        //worker(event)
    SW_SERVER_CB_onClose,          //worker(event)
    SW_SERVER_CB_onPacket,         //worker(event)
    SW_SERVER_CB_onRequest,        //http server
    SW_SERVER_CB_onHandShake,      //worker(event)
    SW_SERVER_CB_onOpen,           //worker(event)
    SW_SERVER_CB_onMessage,        //worker(event)
    SW_SERVER_CB_onBufferFull,     //worker(event)
    SW_SERVER_CB_onBufferEmpty,    //worker(event)
};

#define PHP_SWOOLE_SERVER_CALLBACK_NUM         (SW_SERVER_CB_onPipeMessage + 1)
#define PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM    (SW_SERVER_CB_onBufferEmpty + 1)

typedef struct
{
    zval *callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zend_fcall_info_cache *caches[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    zval _callbacks[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM];
    swServer *serv;
    swListenPort *port;
    zval *zsetting;
} php_swoole_server_port_property;
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 12)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
enum php_swoole_fd_type
{
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
    /**
     * for Co::fread/Co::fwrite
     */
    PHP_SWOOLE_FD_CO_UTIL,
};
//---------------------------------------------------------
typedef enum
{
    PHP_SWOOLE_RINIT_BEGIN,
    PHP_SWOOLE_RINIT_END,
    PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN,
    PHP_SWOOLE_RSHUTDOWN_BEGIN,
    PHP_SWOOLE_RSHUTDOWN_END,
} php_swoole_req_status;
//---------------------------------------------------------
typedef struct
{
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;
} php_swoole_fci;
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL))

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_event_ce;
extern zend_class_entry *swoole_timer_ce;
extern zend_class_entry *swoole_socket_coro_ce;
extern zend_class_entry *swoole_client_ce;
extern zend_class_entry *swoole_server_ce;
extern zend_object_handlers swoole_server_handlers;
extern zend_class_entry *swoole_connection_iterator_ce;
extern zend_class_entry *swoole_buffer_ce;
extern zend_class_entry *swoole_process_ce;
extern zend_class_entry *swoole_http_server_ce;
extern zend_object_handlers swoole_http_server_handlers;
extern zend_class_entry *swoole_websocket_server_ce;
extern zend_class_entry *swoole_websocket_frame_ce;
extern zend_class_entry *swoole_server_port_ce;
extern zend_class_entry *swoole_exception_ce;
extern zend_object_handlers swoole_exception_handlers;

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_cpu_num);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_get_local_ip);
PHP_FUNCTION(swoole_get_local_mac);
PHP_FUNCTION(swoole_clear_dns_cache);
PHP_FUNCTION(swoole_internal_call_user_shutdown_begin);
//---------------------------------------------------------
//                  Coroutine API
//---------------------------------------------------------
PHP_FUNCTION(swoole_coroutine_create);
PHP_FUNCTION(swoole_coroutine_exec);
PHP_FUNCTION(swoole_coroutine_gethostbyname);
PHP_FUNCTION(swoole_coroutine_defer);
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
#define SW_STRERROR_SYSTEM  0
#define SW_STRERROR_GAI     1
#define SW_STRERROR_DNS     2
#define SW_STRERROR_SWOOLE  9

PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);
PHP_FUNCTION(swoole_last_error);


/**
 * MINIT <Sort by dependency>
 * ==============================================================
 */
void php_swoole_event_minit(int module_number);
// base
void php_swoole_atomic_minit(int module_number);
void php_swoole_buffer_minit(int module_number);
void php_swoole_lock_minit(int module_number);
void php_swoole_process_minit(int module_number);
void php_swoole_process_pool_minit(int module_number);
void php_swoole_table_minit(int module_number);
void php_swoole_timer_minit(int module_number);
// coroutine
void php_swoole_async_coro_minit(int module_number);
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
 * RSHUTDOWN
 * ==============================================================
 */
void php_swoole_async_coro_rshutdown();
void php_swoole_redis_server_rshutdown();
void php_swoole_coroutine_rshutdown();
void php_swoole_runtime_rshutdown();
void php_swoole_server_rshutdown();

void php_swoole_process_clean();
int php_swoole_process_start(swWorker *process, zval *zobject);

int php_swoole_reactor_init();

// shutdown
void php_swoole_register_shutdown_function(const char *function);
void php_swoole_register_shutdown_function_prepend(const char *function);
void php_swoole_register_rshutdown_callback(swCallback cb, void *private_data);

// event
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_event_exit();

void php_swoole_server_register_callbacks(swServer *serv);
swClient* php_swoole_client_new(zval *zobject, char *host, int host_len, int port);
void php_swoole_client_check_setting(swClient *cli, zval *zset);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset);
#endif

static sw_inline zend_bool php_swoole_websocket_frame_is_object(zval *zdata)
{
    return Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_websocket_frame_ce);
}

#ifdef SW_HAVE_ZLIB
#define php_swoole_websocket_frame_pack        php_swoole_websocket_frame_pack_ex
#define php_swoole_websocket_frame_object_pack php_swoole_websocket_frame_object_pack_ex
#else
#define php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags, mask, allow_compress) \
        php_swoole_websocket_frame_pack_ex(buffer, zdata, opcode, flags, mask, 0)
#define php_swoole_websocket_frame_object_pack(buffer, zdata, mask, allow_compress) \
        php_swoole_websocket_frame_object_pack_ex(buffer, zdata, mask, 0)
#endif
int php_swoole_websocket_frame_pack_ex(swString *buffer, zval *zdata, zend_long opcode, uint8_t flags, zend_bool mask, zend_bool allow_compress);
int php_swoole_websocket_frame_object_pack_ex(swString *buffer, zval *zdata, zend_bool mask, zend_bool allow_compress);
void php_swoole_websocket_frame_unpack(swString *data, zval *zframe);
void php_swoole_websocket_frame_unpack_ex(swString *data, zval *zframe, uchar allow_uncompress);

int php_swoole_task_pack(swEventData *task, zval *data);
zval* php_swoole_task_unpack(swEventData *task_result);

#ifdef SW_HAVE_ZLIB
int php_swoole_zlib_decompress(z_stream *stream, swString *buffer, char *body, int length);
#endif

int swoole_convert_to_fd(zval *zsocket);
int swoole_convert_to_fd_ex(zval *zsocket, int *async);

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *swoole_convert_to_socket(int sock);
void swoole_php_socket_free(zval *zsocket);
#endif

zend_fcall_info_cache* php_swoole_server_get_fci_cache(swServer *serv, int server_fd, int event_type);
int php_swoole_create_dir(const char* path, size_t length);
void php_swoole_server_before_start(swServer *serv, zval *zobject);
void php_swoole_http_server_init_global_variant();
void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value);
void php_swoole_get_recv_data(swServer *serv, zval *zdata, swEventData *req, char *header, uint32_t header_length);
size_t php_swoole_get_send_data(zval *zdata, char **str);
void php_swoole_onConnect(swServer *, swDataHead *);
int php_swoole_onReceive(swServer *, swEventData *);
int php_swoole_http_onReceive(swServer *, swEventData *);
void php_swoole_http_onClose(swServer *, swDataHead *);
int php_swoole_onPacket(swServer *, swEventData *);
void php_swoole_onClose(swServer *, swDataHead *);
void php_swoole_onBufferFull(swServer *, swDataHead *);
void php_swoole_onBufferEmpty(swServer *, swDataHead *);
ssize_t php_swoole_length_func(swProtocol *protocol, swSocket *_socket, char *data, uint32_t length);
int php_swoole_client_onPackage(swConnection *conn, char *data, uint32_t length);
zend_bool php_swoole_signal_isset_handler(int signo);

#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset);
#endif

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_shortname;
    zend_bool enable_coroutine;
    zend_bool enable_preemptive_scheduler;
    zend_bool enable_library;
    long socket_buffer_size;
    php_swoole_req_status req_status;
    swLinkedList *rshutdown_functions;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

/* PHP 7 compatibility patches */

// Fixed C++ warning (https://github.com/php/php-src/commit/ec31924cd68df4f5591664d487baaba0d01b1daf)
#if PHP_VERSION_ID < 70200
#define sw_zend_bailout() _sw_zend_bailout(__FILE__, __LINE__)
static sw_inline void _sw_zend_bailout(const char *filename, uint32_t lineno)
{
    _zend_bailout((char *)filename, lineno);
}
#else
#define sw_zend_bailout() zend_bailout()
#endif

// Fixed in php-7.0.28, php-7.1.15RC1, php-7.2.3RC1 (https://github.com/php/php-src/commit/e88e83d3e5c33fcd76f08b23e1a2e4e8dc98ce41)
#if PHP_MAJOR_VERSION == 7 && ((PHP_MINOR_VERSION == 0 && PHP_RELEASE_VERSION < 28) || (PHP_MINOR_VERSION == 1 && PHP_RELEASE_VERSION < 15) || (PHP_MINOR_VERSION == 2 && PHP_RELEASE_VERSION < 3))
// See https://github.com/php/php-src/commit/0495bf5650995cd8f18d6a9909eb4c5dcefde669
// Then https://github.com/php/php-src/commit/2dcfd8d16f5fa69582015cbd882aff833075a34c
#if PHP_VERSION_ID < 70100
#define zend_wrong_parameters_count_error zend_wrong_paramers_count_error
#endif

// See https://github.com/php/php-src/commit/52db03b3e52bfc886896925d050af79bc4dc1ba3
#if PHP_MINOR_VERSION == 2
#define SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR zend_wrong_parameters_count_error(_flags & ZEND_PARSE_PARAMS_THROW, _num_args, _min_num_args, _max_num_args)
#else
#define SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR zend_wrong_parameters_count_error(_num_args, _min_num_args, _max_num_args)
#endif

#undef ZEND_PARSE_PARAMETERS_START_EX

#define ZEND_PARSE_PARAMETERS_START_EX(flags, min_num_args, max_num_args) do { \
        const int _flags = (flags); \
        int _min_num_args = (min_num_args); \
        int _max_num_args = (max_num_args); \
        int _num_args = EX_NUM_ARGS(); \
        int _i; \
        zval *_real_arg, *_arg = NULL; \
        zend_expected_type _expected_type = Z_EXPECTED_LONG; \
        char *_error = NULL; \
        zend_bool _dummy; \
        zend_bool _optional = 0; \
        int error_code = ZPP_ERROR_OK; \
        ((void)_i); \
        ((void)_real_arg); \
        ((void)_arg); \
        ((void)_expected_type); \
        ((void)_error); \
        ((void)_dummy); \
        ((void)_optional); \
        \
        do { \
            if (UNEXPECTED(_num_args < _min_num_args) || \
                (UNEXPECTED(_num_args > _max_num_args) && \
                 EXPECTED(_max_num_args >= 0))) { \
                if (!(_flags & ZEND_PARSE_PARAMS_QUIET)) { \
                    SW_ZEND_WRONG_PARAMETERS_COUNT_ERROR; \
                } \
                error_code = ZPP_ERROR_FAILURE; \
                break; \
            } \
            _i = 0; \
            _real_arg = ZEND_CALL_ARG(execute_data, 0);
#endif

/* PHP 7.3 compatibility macro {{{*/
#ifndef GC_SET_REFCOUNT
# define GC_SET_REFCOUNT(p, rc) do { \
    GC_REFCOUNT(p) = rc; \
} while (0)
#endif

#ifndef GC_ADDREF
#define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
#define GC_DELREF(ref) --GC_REFCOUNT(ref)
#endif

#ifndef GC_IS_RECURSIVE
#define GC_IS_RECURSIVE(p) \
    (ZEND_HASH_GET_APPLY_COUNT(p) >= 1)
#define GC_PROTECT_RECURSION(p) \
    ZEND_HASH_INC_APPLY_COUNT(p)
#define GC_UNPROTECT_RECURSION(p) \
    ZEND_HASH_DEC_APPLY_COUNT(p)
#endif

#ifndef ZEND_CLOSURE_OBJECT
#define ZEND_CLOSURE_OBJECT(func) (zend_object*)func->op_array.prototype
#endif

#ifndef ZEND_HASH_APPLY_PROTECTION
#define ZEND_HASH_APPLY_PROTECTION(p) 1
#endif/*}}}*/

/* PHP 7.4 compatibility macro {{{*/
#ifndef E_FATAL_ERRORS
#define E_FATAL_ERRORS (E_ERROR | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR | E_PARSE)
#endif

#ifndef ZEND_THIS
#define ZEND_THIS (&EX(This))
#endif
/*}}}*/

/* PHP 7 wrapper functions / macros */

//----------------------------------Zval API------------------------------------

// ide-helper
#ifdef SW_DEBUG
#undef RETURN_BOOL
#undef RETURN_NULL
#undef RETURN_LONG
#undef RETURN_DOUBLE
#undef RETURN_STR
#undef RETURN_INTERNED_STR
#undef RETURN_NEW_STR
#undef RETURN_STR_COPY
#undef RETURN_STRING
#undef RETURN_STRINGL
#undef RETURN_EMPTY_STRING
#undef RETURN_RES
#undef RETURN_ARR
#undef RETURN_EMPTY_ARRAY
#undef RETURN_OBJ
#undef RETURN_ZVAL
#undef RETURN_FALSE
#undef RETURN_TRUE
#undef ZVAL_LONG
#undef ZVAL_DOUBLE
#define RETURN_BOOL(b)                  do { RETVAL_BOOL(b); return; } while (0)
#define RETURN_NULL()                   do { RETVAL_NULL(); return;} while (0)
#define RETURN_LONG(l)                  do { RETVAL_LONG(l); return; } while (0)
#define RETURN_DOUBLE(d)                do { RETVAL_DOUBLE(d); return; } while (0)
#define RETURN_STR(s)                   do { RETVAL_STR(s); return; } while (0)
#define RETURN_INTERNED_STR(s)          do { RETVAL_INTERNED_STR(s); return; } while (0)
#define RETURN_NEW_STR(s)               do { RETVAL_NEW_STR(s); return; } while (0)
#define RETURN_STR_COPY(s)              do { RETVAL_STR_COPY(s); return; } while (0)
#define RETURN_STRING(s)                do { RETVAL_STRING(s); return; } while (0)
#define RETURN_STRINGL(s, l)            do { RETVAL_STRINGL(s, l); return; } while (0)
#define RETURN_EMPTY_STRING()           do { RETVAL_EMPTY_STRING(); return; } while (0)
#define RETURN_RES(r)                   do { RETVAL_RES(r); return; } while (0)
#define RETURN_ARR(r)                   do { RETVAL_ARR(r); return; } while (0)
#define RETURN_EMPTY_ARRAY()            do { RETVAL_EMPTY_ARRAY(); return; } while (0)
#define RETURN_OBJ(r)                   do { RETVAL_OBJ(r); return; } while (0)
#define RETURN_ZVAL(zv, copy, dtor)     do { RETVAL_ZVAL(zv, copy, dtor); return; } while (0)
#define RETURN_FALSE                    do { RETVAL_FALSE; return; } while (0)
#define RETURN_TRUE                     do { RETVAL_TRUE; return; } while (0)
#define ZVAL_LONG(z, l) do {            \
        zval *__z = (z);                \
        Z_LVAL_P(__z) = l;              \
        Z_TYPE_INFO_P(__z) = IS_LONG;   \
    } while (0)
#define ZVAL_DOUBLE(z, d) do {          \
        zval *__z = (z);                \
        Z_DVAL_P(__z) = d;              \
        Z_TYPE_INFO_P(__z) = IS_DOUBLE; \
    } while (0)
#endif

// Deprecated: do not use it anymore
// do not use sw_copy_to_stack(return_value, foo);
#define sw_copy_to_stack(ptr, val) do { \
    (val) = *(zval *) (ptr); \
    (ptr) = &(val); \
} while (0)

#define SW_ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#ifndef ZVAL_IS_BOOL
static sw_inline zend_bool ZVAL_IS_BOOL(zval *v)
{
    return Z_TYPE_P(v) == IS_TRUE || Z_TYPE_P(v) == IS_FALSE;
}
#endif

#ifndef Z_BVAL_P
static sw_inline zend_bool Z_BVAL_P(zval *v)
{
    return Z_TYPE_P(v) == IS_TRUE;
}
#endif

#ifndef ZVAL_IS_ARRAY
static sw_inline zend_bool ZVAL_IS_ARRAY(zval *v)
{
    return Z_TYPE_P(v) == IS_ARRAY;
}
#endif

static sw_inline zval* sw_malloc_zval()
{
    return (zval *) emalloc(sizeof(zval));
}

static sw_inline zval* sw_zval_dup(zval *val)
{
    zval *dup = sw_malloc_zval();
    memcpy(dup, val, sizeof(zval));
    return dup;
}

static sw_inline void sw_zval_free(zval *val)
{
    zval_ptr_dtor(val);
    efree(val);
}

//----------------------------------Constant API------------------------------------

#define SW_REGISTER_NULL_CONSTANT(name)           REGISTER_NULL_CONSTANT(name, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_BOOL_CONSTANT(name, value)    REGISTER_BOOL_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_LONG_CONSTANT(name, value)    REGISTER_LONG_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_DOUBLE_CONSTANT(name, value)  REGISTER_DOUBLE_CONSTANT(name, value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_STRING_CONSTANT(name, value)  REGISTER_STRING_CONSTANT(name, (char *) value, CONST_CS | CONST_PERSISTENT)
#define SW_REGISTER_STRINGL_CONSTANT(name, value) REGISTER_STRINGL_CONSTANT(name, (char *) value, CONST_CS | CONST_PERSISTENT)

//----------------------------------Number API-----------------------------------

#define sw_php_math_round(value, places, mode) _php_math_round(value, places, mode)

//----------------------------------String API-----------------------------------

#define SW_PHP_OB_START(zoutput) \
    zval zoutput; \
    do { \
        php_output_start_user(NULL, 0, PHP_OUTPUT_HANDLER_STDFLAGS);
#define SW_PHP_OB_END() \
        php_output_get_contents(&zoutput); \
        php_output_discard(); \
    } while (0)

static sw_inline zend_string* sw_zend_string_recycle(zend_string *s, size_t alloc_len, size_t real_len)
{
    SW_ASSERT(!ZSTR_IS_INTERNED(s));
    if (UNEXPECTED(alloc_len != real_len))
    {
        if (UNEXPECTED(alloc_len - real_len > SwooleG.pagesize))
        {
            s = zend_string_realloc(s, real_len, 0);
        }
        else
        {
            ZSTR_LEN(s) = real_len;
        }
    }
    ZSTR_VAL(s)[real_len] = '\0';
    return s;
}

//----------------------------------Array API------------------------------------

#define php_swoole_array_length(zarray)        zend_hash_num_elements(Z_ARRVAL_P(zarray))
#define php_swoole_array_get_value(ht, str, v) ((v = zend_hash_str_find(ht, str, sizeof(str)-1)) && !ZVAL_IS_NULL(v))

static sw_inline int php_swoole_array_length_safe(zval *zarray)
{
    if (zarray && ZVAL_IS_ARRAY(zarray))
    {
        return php_swoole_array_length(zarray);
    }
    else
    {
        return 0;
    }
}

#define SW_HASHTABLE_FOREACH_START(ht, _val) ZEND_HASH_FOREACH_VAL(ht, _val);  {
#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, _val) zend_string *_foreach_key;\
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, _foreach_key, _val); \
    if (!_foreach_key) {k = NULL; klen = 0; ktype = 0;} \
    else {k = ZSTR_VAL(_foreach_key), klen=ZSTR_LEN(_foreach_key); ktype = 1;} {
#define SW_HASHTABLE_FOREACH_END()                 } ZEND_HASH_FOREACH_END();

static sw_inline int add_assoc_ulong_safe_ex(zval *arg, const char *key, size_t key_len, zend_ulong value)
{
    if (sw_likely(value <= ZEND_LONG_MAX))
    {
        return add_assoc_long_ex(arg, key, key_len, value);
    }
    else
    {
        char buf[MAX_LENGTH_OF_LONG + 1];
        size_t len = sw_snprintf(buf, sizeof(buf), ZEND_ULONG_FMT, value);
        return add_assoc_stringl_ex(arg, key, key_len, buf, len);
    }
}

static sw_inline int add_assoc_ulong_safe(zval *arg, const char *key, zend_ulong value)
{
    return add_assoc_ulong_safe_ex(arg, key, strlen(key), value);
}

//----------------------------------Class API------------------------------------

#define SW_Z_OBJCE_NAME_VAL_P(zobject) ZSTR_VAL(Z_OBJCE_P(zobject)->name)

/* PHP 7 class declaration macros */

#define SW_INIT_CLASS_ENTRY_BASE(module, namespaceName, snake_name, shortName, methods, parent_ce) do { \
    zend_class_entry _##module##_ce; \
    INIT_CLASS_ENTRY(_##module##_ce, namespaceName, methods); \
    module##_ce = zend_register_internal_class_ex(&_##module##_ce, parent_ce); \
    SW_CLASS_ALIAS(snake_name, module); \
    SW_CLASS_ALIAS_SHORT_NAME(shortName, module); \
} while (0)

#define SW_INIT_CLASS_ENTRY(module, namespaceName, snake_name, shortName, methods) \
    SW_INIT_CLASS_ENTRY_BASE(module, namespaceName, snake_name, shortName, methods, NULL); \
    memcpy(&module##_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers))

#define SW_INIT_CLASS_ENTRY_EX(module, namespaceName, snake_name, shortName, methods, parent_module) \
    SW_INIT_CLASS_ENTRY_BASE(module, namespaceName, snake_name, shortName, methods, parent_module##_ce); \
    memcpy(&module##_handlers, &parent_module##_handlers, sizeof(zend_object_handlers))

#define SW_INIT_CLASS_ENTRY_EX2(module, namespaceName, snake_name, shortName, methods, parent_module_ce, parent_module_handlers) \
    SW_INIT_CLASS_ENTRY_BASE(module, namespaceName, snake_name, shortName, methods, parent_module_ce); \
    memcpy(&module##_handlers, parent_module_handlers, sizeof(zend_object_handlers))

#define SW_CLASS_ALIAS(name, module) do { \
    if (name) { \
        sw_zend_register_class_alias(ZEND_STRL(name), module##_ce); \
    } \
} while (0)

#define SW_CLASS_ALIAS_SHORT_NAME(shortName, module) do { \
    if (SWOOLE_G(use_shortname)) { \
        SW_CLASS_ALIAS(shortName, module); \
    } \
} while (0)

#define SW_SET_CLASS_SERIALIZABLE(module, _serialize, _unserialize) \
    module##_ce->serialize = _serialize; \
    module##_ce->unserialize = _unserialize

#define sw_zend_class_clone_deny NULL
#define SW_SET_CLASS_CLONEABLE(module, _clone_obj) \
    module##_handlers.clone_obj = _clone_obj

#define SW_SET_CLASS_UNSET_PROPERTY_HANDLER(module, _unset_property) \
    module##_handlers.unset_property = _unset_property

#define SW_SET_CLASS_CREATE(module, _create_object) \
    module##_ce->create_object = _create_object

#define SW_SET_CLASS_DTOR(module, _dtor_obj) \
    module##_handlers.dtor_obj = _dtor_obj

#define SW_SET_CLASS_FREE(module, _free_obj) \
    module##_handlers.free_obj = _free_obj

#define SW_SET_CLASS_CREATE_AND_FREE(module, _create_object, _free_obj) \
    SW_SET_CLASS_CREATE(module, _create_object); \
    SW_SET_CLASS_FREE(module, _free_obj)

#define SW_SET_CLASS_CUSTOM_OBJECT(module, _create_object, _free_obj, _struct, _std) \
    SW_SET_CLASS_CREATE_AND_FREE(module, _create_object, _free_obj); \
    module##_handlers.offset = XtOffsetOf(_struct, _std)

#define SW_PREVENT_USER_DESTRUCT()  do { \
    if (sw_unlikely(!(GC_FLAGS(Z_OBJ_P(ZEND_THIS)) & IS_OBJ_DESTRUCTOR_CALLED))) { \
        RETURN_NULL(); \
    } \
} while (0)

#define SW_FUNCTION_ALIAS(origin_function_table, origin, alias_function_table, alias) \
    sw_zend_register_function_alias(origin_function_table, ZEND_STRL(origin), alias_function_table, ZEND_STRL(alias))

static sw_inline int sw_zend_register_function_alias
(
    HashTable *origin_function_table, const char *origin, size_t origin_length,
    HashTable *alias_function_table, const char *alias, size_t alias_length
)
{
    zend_string *lowercase_origin = zend_string_alloc(origin_length, 0);
    zend_str_tolower_copy(ZSTR_VAL(lowercase_origin), origin, origin_length);
    zend_function *origin_function = (zend_function *) zend_hash_find_ptr(origin_function_table, lowercase_origin);
    zend_string_release(lowercase_origin);
    if (UNEXPECTED(!origin_function))
    {
        return FAILURE;
    }
    SW_ASSERT(origin_function->common.type == ZEND_INTERNAL_FUNCTION);
    char *_alias = (char *) emalloc(alias_length + 1);
    ((char *) memcpy(_alias, alias, alias_length))[alias_length] = '\0';
    zend_function_entry zfe[] = {{_alias, origin_function->internal_function.handler, ((zend_internal_arg_info *) origin_function->common.arg_info) - 1, origin_function->common.num_args, 0 }, PHP_FE_END};
    int ret = zend_register_functions(origin_function->common.scope, zfe, alias_function_table, origin_function->common.type);
    efree(_alias);
    return ret;
}

static sw_inline int sw_zend_register_class_alias(const char *name, size_t name_len, zend_class_entry *ce)
{
    zend_string *_name;
    if (name[0] == '\\')
    {
        _name = zend_string_init(name, name_len, 1);
        zend_str_tolower_copy(ZSTR_VAL(_name), name + 1, name_len - 1);
    }
    else
    {
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
static zend_always_inline void *zend_object_alloc(size_t obj_size, zend_class_entry *ce)
{
    void *obj = emalloc(obj_size + zend_object_properties_size(ce));
    /* Subtraction of sizeof(zval) is necessary, because zend_object_properties_size() may be
     * -sizeof(zval), if the object has no properties. */
    memset(obj, 0, obj_size - sizeof(zval));
    return obj;
}
#endif

static sw_inline zend_object *sw_zend_create_object(zend_class_entry *ce, zend_object_handlers *handlers)
{
    zend_object* object = (zend_object *) zend_object_alloc(sizeof(zend_object), ce);
    zend_object_std_init(object, ce);
    object_properties_init(object, ce);
    object->handlers = handlers;
    return object;
}

static sw_inline zend_object* sw_zend_create_object_deny(zend_class_entry *ce)
{
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
static sw_inline void sw_zend_class_unset_property_deny(zval *zobject, zval *zmember, void **cache_slot)
{
    zend_class_entry *ce = Z_OBJCE_P(zobject);
    while (ce->parent)
    {
        ce = ce->parent;
    }
    SW_ASSERT(ce->type == ZEND_INTERNAL_CLASS);
    if (EXPECTED(zend_hash_find(&ce->properties_info, Z_STR_P(zmember))))
    {
        zend_throw_error(NULL, "Property %s of class %s cannot be unset", Z_STRVAL_P(zmember), SW_Z_OBJCE_NAME_VAL_P(zobject));
        return;
    }
    std_object_handlers.unset_property(zobject, zmember, cache_slot);
}
#else
static sw_inline void sw_zend_class_unset_property_deny(zend_object *object, zend_string *member, void **cache_slot)
{
    zend_class_entry *ce = object->ce;
    while (ce->parent)
    {
        ce = ce->parent;
    }
    SW_ASSERT(ce->type == ZEND_INTERNAL_CLASS);
    if (EXPECTED(zend_hash_find(&ce->properties_info, member)))
    {
        zend_throw_error(NULL, "Property %s of class %s cannot be unset", ZSTR_VAL(member), ZSTR_VAL(object->ce->name));
        return;
    }
    std_object_handlers.unset_property(object, member, cache_slot);
}
#endif

static sw_inline zval* sw_zend_read_property(zend_class_entry *ce, zval *obj, const char *s, int len, int silent)
{
    zval rv, *property = zend_read_property(ce, obj, s, len, silent, &rv);
    if (UNEXPECTED(property == &EG(uninitialized_zval)))
    {
        zend_update_property_null(ce, obj, s, len);
        return zend_read_property(ce, obj, s, len, silent, &rv);
    }
    return property;
}

static sw_inline zval* sw_zend_read_property_not_null(zend_class_entry *ce, zval *obj, const char *s, int len, int silent)
{
    zval rv, *property = zend_read_property(ce, obj, s, len, silent, &rv);
    zend_uchar type = Z_TYPE_P(property);
    return (type == IS_NULL || UNEXPECTED(type == IS_UNDEF)) ? NULL : property;
}

static sw_inline zval *sw_zend_update_and_read_property_array(zend_class_entry *ce, zval *obj, const char *s, int len)
{
    zval ztmp;
    array_init(&ztmp);
    zend_update_property(ce, obj, s, len, &ztmp);
    zval_ptr_dtor(&ztmp);
    return zend_read_property(ce, obj, s, len, 1, &ztmp);
}

static sw_inline zval* sw_zend_read_and_convert_property_array(zend_class_entry *ce, zval *obj, const char *s, int len, int silent)
{
    zval rv, *property = zend_read_property(ce, obj, s, len, silent, &rv);
    if (Z_TYPE_P(property) != IS_ARRAY)
    {
        // NOTICE: if user unset the property, zend_read_property will return uninitialized_zval instead of NULL pointer
        if (UNEXPECTED(property == &EG(uninitialized_zval)))
        {
            property = sw_zend_update_and_read_property_array(ce, obj, s, len);
        }
        else
        {
            zval_ptr_dtor(property);
            array_init(property);
        }
    }

    return property;
}

#define SW_RETURN_PROPERTY(name) do { \
    RETURN_ZVAL(sw_zend_read_property(Z_OBJCE_P(ZEND_THIS), ZEND_THIS, ZEND_STRL(name), 0), 1, 0); \
} while (0)

//----------------------------------Function API------------------------------------

#if PHP_VERSION_ID < 80000
#define sw_zend7_object      zval
#define SW_Z7_OBJ_P(object)  Z_OBJ_P(object)
#define SW_Z8_OBJ_P(zobj)    zobj
#else
#define sw_zend7_object      zend_object
#define SW_Z7_OBJ_P(object)  object
#define SW_Z8_OBJ_P(zobj)    Z_OBJ_P(zobj)
#endif

/**
 * Notice (sw_zend_call_method_with_%u_params): If you don't want to check the return value, please set retval to NULL
 */
#define sw_zend_call_method_with_0_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval) \
        zend_call_method_with_0_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval)

#define sw_zend_call_method_with_1_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval, v1) \
        zend_call_method_with_1_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval, v1)

#define sw_zend_call_method_with_2_params(zobj, obj_ce, fn_ptr_ptr, fn_name, retval, v1, v2) \
        zend_call_method_with_2_params(SW_Z8_OBJ_P(zobj), obj_ce, fn_ptr_ptr, fn_name, retval, v1, v2)

static sw_inline int sw_zend_function_max_num_args(zend_function *function)
{
    // https://github.com/php/php-src/commit/2646f7bcb98dcdd322ea21701c8bb101104ea619
    // zend_function.common.num_args don't include the variadic argument anymore.
    return (function->common.fn_flags & ZEND_ACC_VARIADIC) ? UINT32_MAX : function->common.num_args;
}

// TODO: remove it after remove async modules
static sw_inline zend_bool sw_zend_is_callable(zval *callable, int check_flags, char **callable_name)
{
    zend_string *name;
    zend_bool ret = zend_is_callable(callable, check_flags, &name);
    *callable_name = estrndup(ZSTR_VAL(name), ZSTR_LEN(name));
    zend_string_release(name);
    return ret;
}

static sw_inline zend_bool sw_zend_is_callable_ex(zval *zcallable, zval *zobject, uint check_flags, char **callable_name, size_t *callable_name_len, zend_fcall_info_cache *fci_cache, char **error)
{
    zend_string *name;
    zend_bool ret = zend_is_callable_ex(zcallable, zobject ? Z_OBJ_P(zobject) : NULL, check_flags, &name, fci_cache, error);
    if (callable_name)
    {
        *callable_name = estrndup(ZSTR_VAL(name), ZSTR_LEN(name));
    }
    if (callable_name_len)
    {
        *callable_name_len = ZSTR_LEN(name);
    }
    zend_string_release(name);
    return ret;
}

/* this API can work well when retval is NULL */
static sw_inline int sw_zend_call_function_ex(zval *function_name, zend_fcall_info_cache *fci_cache, uint32_t param_count, zval *params, zval *retval)
{
    zend_fcall_info fci;
    zval _retval;
    int ret;

    fci.size = sizeof(fci);
    fci.object = NULL;
    if (!fci_cache || !fci_cache->function_handler)
    {
        if (!function_name)
        {
            php_swoole_fatal_error(E_WARNING, "Bad function");
            return FAILURE;
        }
        ZVAL_COPY_VALUE(&fci.function_name, function_name);
    }
    else
    {
        ZVAL_UNDEF(&fci.function_name);
    }
    fci.retval = retval ? retval : &_retval;
    fci.param_count = param_count;
    fci.params = params;
    fci.no_separation = 0;

    ret = zend_call_function(&fci, fci_cache);

    if (!retval)
    {
        zval_ptr_dtor(&_retval);
    }
    return ret;
}

/* we must check for exception immediately if we don't have chances to go back to ZendVM (e.g event loop) */
static sw_inline int sw_zend_call_function_ex2(zval *function_name, zend_fcall_info_cache *fci_cache, uint32_t param_count, zval *params, zval *retval)
{
    int ret = sw_zend_call_function_ex(function_name, fci_cache, param_count, params, retval);
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    return ret;
}

static sw_inline int sw_zend_call_function_anyway(zend_fcall_info *fci, zend_fcall_info_cache *fci_cache)
{
    zval retval;
    zend_object* exception = EG(exception);
    if (exception)
    {
        EG(exception) = NULL;
    }
    if (!fci->retval)
    {
        fci->retval = &retval;
    }
    int ret = zend_call_function(fci, fci_cache);
    if (fci->retval == &retval)
    {
        zval_ptr_dtor(&retval);
    }
    if (exception)
    {
        EG(exception) = exception;
    }
    return ret;
}

static sw_inline void sw_zend_fci_params_persist(zend_fcall_info *fci)
{
    if (fci->param_count > 0)
    {
        uint32_t i;
        zval *params = (zval *) ecalloc(fci->param_count, sizeof(zval));
        for (i = 0; i < fci->param_count; i++)
        {
            ZVAL_COPY(&params[i], &fci->params[i]);
        }
        fci->params = params;
    }
}

static sw_inline void sw_zend_fci_params_discard(zend_fcall_info *fci)
{
    if (fci->param_count > 0)
    {
        uint32_t i;
        for (i = 0; i < fci->param_count; i++)
        {
            zval_ptr_dtor(&fci->params[i]);
        }
        efree(fci->params);
    }
}

static sw_inline void sw_zend_fci_cache_persist(zend_fcall_info_cache *fci_cache)
{
    if (fci_cache->object)
    {
        GC_ADDREF(fci_cache->object);
    }
    if (fci_cache->function_handler->op_array.fn_flags & ZEND_ACC_CLOSURE)
    {
        GC_ADDREF(ZEND_CLOSURE_OBJECT(fci_cache->function_handler));
    }
}

static sw_inline void sw_zend_fci_cache_discard(zend_fcall_info_cache *fci_cache)
{
    if (fci_cache->object)
    {
        OBJ_RELEASE(fci_cache->object);
    }
    if (fci_cache->function_handler->op_array.fn_flags & ZEND_ACC_CLOSURE)
    {
        OBJ_RELEASE(ZEND_CLOSURE_OBJECT(fci_cache->function_handler));
    }
}

/* use void* to match some C callback function pointers */
static sw_inline void sw_zend_fci_cache_free(void* fci_cache)
{
    sw_zend_fci_cache_discard((zend_fcall_info_cache *) fci_cache);
    efree((zend_fcall_info_cache *) fci_cache);
}

//----------------------------------Misc API------------------------------------

static sw_inline int php_swoole_check_reactor()
{
    if (SWOOLE_G(req_status) == PHP_SWOOLE_RSHUTDOWN_BEGIN)
    {
        return -1;
    }
    if (sw_unlikely(!sw_reactor()))
    {
        return php_swoole_reactor_init() == SW_OK ? 1 : -1;
    }
    else
    {
        return 0;
    }
}

static sw_inline char* php_swoole_format_date(char *format, size_t format_len, time_t ts, int localtime)
{
    zend_string *time = php_format_date(format, format_len, ts, localtime);
    char *return_str = estrndup(ZSTR_VAL(time), ZSTR_LEN(time));
    zend_string_release(time);
    return return_str;
}

static sw_inline char* php_swoole_url_encode(char *value, size_t value_len, int* exten)
{
    zend_string *str = php_url_encode(value, value_len);
    *exten = ZSTR_LEN(str);
    char *return_str = estrndup(ZSTR_VAL(str), ZSTR_LEN(str));
    zend_string_release(str);
    return return_str;
}

static sw_inline char* php_swoole_http_build_query(zval *zdata, size_t *length, smart_str *formstr)
{
    if (php_url_encode_hash_ex(HASH_OF(zdata), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
    {
        if (formstr->s)
        {
            smart_str_free(formstr);
        }
        return NULL;
    }
    if (!formstr->s)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->s->len;
    return formstr->s->val;
}

END_EXTERN_C()

#endif /* PHP_SWOOLE_H */
