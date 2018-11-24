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

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"
#include "zend_closures.h"

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
#	define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_SWOOLE_API
#endif

#define SWOOLE_PROPERTY_MAX     32
#define SWOOLE_OBJECT_MAX       10000000

typedef struct
{
    void **array;
    uint32_t size;
    void **property[SWOOLE_PROPERTY_MAX];
    uint32_t property_size[SWOOLE_PROPERTY_MAX];
} swoole_object_array;

#ifdef ZTS
#include "TSRM.h"
extern void ***sw_thread_ctx;
extern __thread swoole_object_array swoole_objects;
#else
extern swoole_object_array swoole_objects;
#endif

// Solaris doesn't have PTRACE_ATTACH
#if defined(HAVE_PTRACE) && defined(__sun)
#undef HAVE_PTRACE
#endif

//#define SW_USE_PHP        1
#define SW_CHECK_RETURN(s)         if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{\
	zend_update_property_long(NULL, getThis(), SW_STRL("errCode"), s);\
	RETURN_FALSE;}return

#define swoole_php_error(level, fmt_str, ...)   if (SWOOLE_G(display_errors)) php_error_docref(NULL, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_fatal_error(level, fmt_str, ...)   php_error_docref(NULL, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_sys_error(level, fmt_str, ...)  if (SWOOLE_G(display_errors)) php_error_docref(NULL, level, fmt_str" Error: %s[%d].", ##__VA_ARGS__, strerror(errno), errno)

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, require openssl library."
#endif
#endif

#ifdef SW_SOCKETS
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#endif

#ifdef SW_USE_HTTP2
#if !defined(HAVE_NGHTTP2)
#error "Enable http2 support, require nghttp2 library."
#else
#include <nghttp2/nghttp2ver.h>
#endif
#endif

#if PHP_VERSION_ID < 70300
#define SW_USE_FAST_SERIALIZE 1
#endif

#if PHP_MAJOR_VERSION < 7
#error "require PHP version 7.0 or later."
#endif

#include "php7_wrapper.h"

#define PHP_CLIENT_CALLBACK_NUM             4
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
    SW_SERVER_CB_onPipeMessage,    //worker(evnet & task)
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
    zval *setting;
    swServer *serv;
    swListenPort *port;
} swoole_server_port_property;
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 12)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
enum php_swoole_fd_type
{
    PHP_SWOOLE_FD_STREAM_CLIENT = SW_FD_STREAM_CLIENT,
    PHP_SWOOLE_FD_DGRAM_CLIENT = SW_FD_DGRAM_CLIENT,
    PHP_SWOOLE_FD_MYSQL,
    PHP_SWOOLE_FD_REDIS,
    PHP_SWOOLE_FD_HTTPCLIENT,
    PHP_SWOOLE_FD_PROCESS_STREAM,
#ifdef SW_COROUTINE
    PHP_SWOOLE_FD_MYSQL_CORO,
    PHP_SWOOLE_FD_REDIS_CORO,
    PHP_SWOOLE_FD_POSTGRESQL,
    PHP_SWOOLE_FD_SOCKET,
#endif
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
    zval _callback;
    zval *callback;
} php_defer_callback;
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL))
#define php_swoole_array_length(array)      zend_hash_num_elements(Z_ARRVAL_P(array))

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;
extern zend_class_entry *swoole_websocket_server_class_entry_ptr;
extern zend_class_entry *swoole_server_port_class_entry_ptr;
extern zend_class_entry *swoole_exception_class_entry_ptr;

extern zval *php_sw_server_callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];
extern zend_fcall_info_cache *php_sw_server_caches[PHP_SWOOLE_SERVER_CALLBACK_NUM];
extern zval _php_sw_server_callbacks[PHP_SWOOLE_SERVER_CALLBACK_NUM];

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
PHP_FUNCTION(swoole_call_user_shutdown_begin);
//---------------------------------------------------------
//                  Coroutine API
//---------------------------------------------------------
PHP_FUNCTION(swoole_coroutine_create);
PHP_FUNCTION(swoole_coroutine_exec);
PHP_FUNCTION(swoole_coroutine_gethostbyname);
PHP_FUNCTION(swoole_coroutine_defer);
//---------------------------------------------------------
//                  swoole_server
//---------------------------------------------------------
PHP_METHOD(swoole_server, __construct);
PHP_METHOD(swoole_server, __destruct);
PHP_METHOD(swoole_server, set);
PHP_METHOD(swoole_server, on);
PHP_METHOD(swoole_server, listen);
PHP_METHOD(swoole_server, sendMessage);
PHP_METHOD(swoole_server, addProcess);
PHP_METHOD(swoole_server, start);
PHP_METHOD(swoole_server, stop);
PHP_METHOD(swoole_server, send);
PHP_METHOD(swoole_server, sendfile);
PHP_METHOD(swoole_server, stats);
PHP_METHOD(swoole_server, bind);
PHP_METHOD(swoole_server, sendto);
PHP_METHOD(swoole_server, sendwait);
PHP_METHOD(swoole_server, exist);
PHP_METHOD(swoole_server, protect);
PHP_METHOD(swoole_server, close);
PHP_METHOD(swoole_server, confirm);
PHP_METHOD(swoole_server, pause);
PHP_METHOD(swoole_server, resume);
PHP_METHOD(swoole_server, task);
PHP_METHOD(swoole_server, taskwait);
PHP_METHOD(swoole_server, taskWaitMulti);
PHP_METHOD(swoole_server, taskCo);
PHP_METHOD(swoole_server, finish);
PHP_METHOD(swoole_server, reload);
PHP_METHOD(swoole_server, shutdown);
PHP_METHOD(swoole_server, getLastError);
PHP_METHOD(swoole_server, heartbeat);
PHP_METHOD(swoole_server, connection_list);
PHP_METHOD(swoole_server, connection_info);
#ifdef SW_BUFFER_RECV_TIME
PHP_METHOD(swoole_server, getReceivedTime);
#endif

PHP_METHOD(swoole_connection_iterator, count);
PHP_METHOD(swoole_connection_iterator, rewind);
PHP_METHOD(swoole_connection_iterator, next);
PHP_METHOD(swoole_connection_iterator, current);
PHP_METHOD(swoole_connection_iterator, key);
PHP_METHOD(swoole_connection_iterator, valid);
PHP_METHOD(swoole_connection_iterator, offsetExists);
PHP_METHOD(swoole_connection_iterator, offsetGet);
PHP_METHOD(swoole_connection_iterator, offsetSet);
PHP_METHOD(swoole_connection_iterator, offsetUnset);
PHP_METHOD(swoole_connection_iterator, __destruct);

#ifdef SWOOLE_SOCKETS_SUPPORT
PHP_METHOD(swoole_server, getSocket);
#endif
//---------------------------------------------------------
//                  swoole_event
//---------------------------------------------------------
PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_set);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_write);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);
PHP_FUNCTION(swoole_event_defer);
PHP_FUNCTION(swoole_event_cycle);
PHP_FUNCTION(swoole_event_dispatch);
PHP_FUNCTION(swoole_event_isset);
PHP_FUNCTION(swoole_client_select);
//---------------------------------------------------------
//                  swoole_async
//---------------------------------------------------------
PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_close);
PHP_FUNCTION(swoole_async_readfile);
PHP_FUNCTION(swoole_async_writefile);
PHP_FUNCTION(swoole_async_dns_lookup);
PHP_FUNCTION(swoole_async_dns_lookup_coro);
PHP_FUNCTION(swoole_async_set);
PHP_METHOD(swoole_async, exec);
//---------------------------------------------------------
//                  swoole_timer
//---------------------------------------------------------
PHP_FUNCTION(swoole_timer_after);
PHP_FUNCTION(swoole_timer_tick);
PHP_FUNCTION(swoole_timer_exists);
PHP_FUNCTION(swoole_timer_clear);
//---------------------------------------------------------
//                  other
//---------------------------------------------------------
PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);
//---------------------------------------------------------
//                  serialize
//---------------------------------------------------------
#ifdef SW_USE_FAST_SERIALIZE
PHP_FUNCTION(swoole_serialize);
PHP_FUNCTION(swoole_fast_serialize);
PHP_FUNCTION(swoole_unserialize);
#endif

void swoole_destroy_table(zend_resource *rsrc);

void swoole_server_port_init(int module_number);
void swoole_async_init(int module_number);
void swoole_table_init(int module_number);
void swoole_runtime_init(int module_number);
void swoole_lock_init(int module_number);
void swoole_atomic_init(int module_number);
void swoole_client_init(int module_number);
void swoole_socket_coro_init(int module_number);
void swoole_client_coro_init(int module_number);
void swoole_redis_coro_init(int module_number);
#ifdef SW_USE_POSTGRESQL
void swoole_postgresql_coro_init (int module_number);
#endif
void swoole_mysql_coro_init(int module_number);
void swoole_http_client_coro_init(int module_number);
void swoole_coroutine_util_init(int module_number);
void swoole_coroutine_util_destroy();
void swoole_http_client_init(int module_number);
void swoole_redis_init(int module_number);
void swoole_redis_server_init(int module_number);
void swoole_process_init(int module_number);
void swoole_process_pool_init(int module_number);
void swoole_http_server_init(int module_number);
#ifdef SW_USE_HTTP2
void swoole_http2_client_coro_init(int module_number);
#endif
void swoole_websocket_init(int module_number);
void swoole_buffer_init(int module_number);
void swoole_mysql_init(int module_number);
void swoole_mmap_init(int module_number);
void swoole_channel_init(int module_number);
void swoole_ringqueue_init(int module_number);
void swoole_msgqueue_init(int module_number);
void swoole_channel_coro_init(int module_number);
#ifdef SW_USE_FAST_SERIALIZE
void swoole_serialize_init(int module_number);
#endif
void swoole_memory_pool_init(int module_number);

void php_swoole_process_clean();
int php_swoole_process_start(swWorker *process, zval *zobject);

void php_swoole_reactor_init();

static sw_inline void php_swoole_check_reactor()
{
    if (unlikely(!SwooleWG.reactor_init))
    {
        php_swoole_reactor_init();
    }
}

void php_swoole_check_aio();
void php_swoole_at_shutdown(char *function);
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_event_exit();
long php_swoole_add_timer(int ms, zval *callback, zval *param, int persistent);
void php_swoole_clear_all_timer();
void php_swoole_register_callback(swServer *serv);
void php_swoole_trace_check(void *arg);
void php_swoole_client_free(zval *zobject, swClient *cli);
swClient* php_swoole_client_new(zval *zobject, char *host, int host_len, int port);
void php_swoole_client_check_setting(swClient *cli, zval *zset);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset);
#endif
void php_swoole_websocket_frame_unpack(swString *data, zval *zframe);
int php_swoole_websocket_frame_pack(swString *buffer, zval *zdata, zend_bool opcode, zend_bool fin, zend_bool mask);
void php_swoole_sha1(const char *str, int _len, unsigned char *digest);

int php_swoole_task_pack(swEventData *task, zval *data);
zval* php_swoole_task_unpack(swEventData *task_result);

static sw_inline void* swoole_get_object(zval *zobject)
{
    uint32_t handle = Z_OBJ_HANDLE_P(zobject);
    assert(handle < swoole_objects.size);
    return swoole_objects.array[handle];
}

static sw_inline void* swoole_get_property(zval *zobject, int property_id)
{
    uint32_t handle = Z_OBJ_HANDLE_P(zobject);
    if (handle >= swoole_objects.property_size[property_id])
    {
        return NULL;
    }
    return swoole_objects.property[property_id][handle];
}

void swoole_set_object(zval *zobject, void *ptr);
void swoole_set_property(zval *zobject, int property_id, void *ptr);
int swoole_convert_to_fd(zval *zfd);
int swoole_convert_to_fd_ex(zval *zfd, int *async);
int swoole_register_rshutdown_function(swCallback func, int push_back);
void swoole_call_rshutdown_function(void *arg);

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *swoole_convert_to_socket(int sock);
#endif

zval* php_swoole_server_get_callback(swServer *serv, int server_fd, int event_type);
zend_fcall_info_cache* php_swoole_server_get_fci_cache(swServer *serv, int server_fd, int event_type);
void php_swoole_server_before_start(swServer *serv, zval *zobject);
void php_swoole_http_server_before_start(swServer *serv, zval *zobject);
void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value);
void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length);
size_t php_swoole_get_send_data(zval *zdata, char **str);
void php_swoole_onConnect(swServer *, swDataHead *);
int php_swoole_onReceive(swServer *, swEventData *);
int php_swoole_http_onReceive(swServer *, swEventData *);
void php_swoole_http_onClose(swServer *, swDataHead *);
int php_swoole_onPacket(swServer *, swEventData *);
void php_swoole_onClose(swServer *, swDataHead *);
void php_swoole_onBufferFull(swServer *, swDataHead *);
void php_swoole_onBufferEmpty(swServer *, swDataHead *);
ssize_t php_swoole_length_func(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
int php_swoole_dispatch_func(swServer *serv, swConnection *conn, swEventData *data);
int php_swoole_client_onPackage(swConnection *conn, char *data, uint32_t length);
void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode);
void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode);
zend_bool php_swoole_signal_isset_handler(int signo);
void php_swoole_event_onDefer(void *_cb);

#ifdef SW_USE_FAST_SERIALIZE
PHPAPI zend_string* php_swoole_serialize(zval *zvalue);
PHPAPI int php_swoole_unserialize(void *buffer, size_t len, zval *return_value, zval *zobject_args, long flag);
#endif

#ifdef SW_COROUTINE
int php_coroutine_reactor_can_exit(swReactor *reactor);
void sw_coro_check_bind(const char *name, long bind_cid);
#endif

#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset);
#endif

static sw_inline int php_swoole_is_callable(zval *callback)
{
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return SW_FALSE;
    }
    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name))
    {
        swoole_php_fatal_error(E_WARNING, "function '%s' is not callable", func_name);
        efree(func_name);
        return SW_FALSE;
    }
    else
    {
        efree(func_name);
        return SW_TRUE;
    }
}

#define php_swoole_array_get_value(ht, str, v)     ((v = zend_hash_str_find(ht, str, sizeof(str)-1)) && !ZVAL_IS_NULL(v))
#define php_swoole_array_separate(arr)       zval *_new_##arr;\
    SW_MAKE_STD_ZVAL(_new_##arr);\
    array_init(_new_##arr);\
    php_array_merge(Z_ARRVAL_P(_new_##arr), Z_ARRVAL_P(arr));\
    arr = _new_##arr;

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_namespace;
    zend_bool use_shortname;
    zend_bool fast_serialize;
    zend_bool enable_coroutine;
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

#define SWOOLE_RAW_DEFINE(constant)    REGISTER_LONG_CONSTANT(#constant, constant, CONST_CS | CONST_PERSISTENT)
#define SWOOLE_DEFINE(constant)    REGISTER_LONG_CONSTANT("SWOOLE_"#constant, SW_##constant, CONST_CS | CONST_PERSISTENT)

#define SWOOLE_INIT_CLASS_ENTRY(ce, name, name_ns, methods) \
    if (SWOOLE_G(use_namespace)) { \
        INIT_CLASS_ENTRY(ce, name_ns, methods); \
    } else { \
        INIT_CLASS_ENTRY(ce, name, methods); \
    }

#define SWOOLE_CLASS_ALIAS(name, name_ns) \
    if (SWOOLE_G(use_namespace)) { \
        sw_zend_register_class_alias(#name, name##_class_entry_ptr);\
    } else { \
        sw_zend_register_class_alias(name_ns, name##_class_entry_ptr);\
    }

/* PHP 7 patches */
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

/* PHP 7.0 compatibility macro {{{*/
#if PHP_VERSION_ID < 70100
#define SW_DECLARE_EG_SCOPE(_scope) zend_class_entry *_scope
#define SW_SAVE_EG_SCOPE(_scope) _scope = EG(scope)
#define SW_SET_EG_SCOPE(_scope) EG(scope) = _scope
#else
#define SW_DECLARE_EG_SCOPE(_scope)
#define SW_SAVE_EG_SCOPE(scope)
#define SW_SET_EG_SCOPE(scope)
#endif/*}}}*/

/* PHP 7.3 forward compatibility */
#ifndef GC_SET_REFCOUNT
# define GC_SET_REFCOUNT(p, rc) do { \
		GC_REFCOUNT(p) = rc; \
	} while (0)
#endif

#ifndef GC_IS_RECURSIVE
# define GC_IS_RECURSIVE(p) \
	(ZEND_HASH_GET_APPLY_COUNT(p) > 1)
# define GC_PROTECT_RECURSION(p) \
	ZEND_HASH_INC_APPLY_COUNT(p)
# define GC_UNPROTECT_RECURSION(p) \
	ZEND_HASH_DEC_APPLY_COUNT(p)
#endif

/* PHP 7.3 compatibility macro {{{*/
#ifndef ZEND_CLOSURE_OBJECT
# define ZEND_CLOSURE_OBJECT(func) (zend_object*)func->op_array.prototype
#endif
#ifndef GC_ADDREF
# define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
# define GC_DELREF(ref) --GC_REFCOUNT(ref)
#endif/*}}}*/

#ifndef ZEND_HASH_APPLY_PROTECTION
# define ZEND_HASH_APPLY_PROTECTION(p) 1
#endif

END_EXTERN_C()

#endif	/* PHP_SWOOLE_H */
