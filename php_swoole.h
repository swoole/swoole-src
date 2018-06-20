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

/* $Id$ */

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "php_streams.h"
#include "php_network.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"
#include <ext/date/php_date.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>
#include <ext/standard/php_array.h>
#include <ext/standard/basic_functions.h>
#include <ext/standard/php_http.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SW_STATIC_COMPILATION
#include "php_config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

BEGIN_EXTERN_C()

#define PHP_SWOOLE_VERSION  "4.0.1"
#define PHP_SWOOLE_CHECK_CALLBACK
#define PHP_SWOOLE_ENABLE_FASTCALL
#define PHP_SWOOLE_CLIENT_USE_POLL

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define SW_HOST_SIZE  128

typedef struct
{
    uint16_t port;
    uint16_t from_fd;
} php_swoole_udp_t;

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

//#define SW_USE_PHP        1
#define SW_CHECK_RETURN(s)         if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{\
	zend_update_property_long(NULL, getThis(), SW_STRL("errCode")-1, s TSRMLS_CC);\
	RETURN_FALSE;}return

#define swoole_php_error(level, fmt_str, ...)   if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_fatal_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_sys_error(level, fmt_str, ...)  if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str" Error: %s[%d].", ##__VA_ARGS__, strerror(errno), errno)
#define swoole_efree(p)  if (p) efree(p)

#if defined(SW_ASYNC_MYSQL)
#if defined(SW_HAVE_MYSQLI) && defined(SW_HAVE_MYSQLND)
#else
#error "Enable async_mysql support, require mysqli and mysqlnd."
#undef SW_ASYNC_MYSQL
#endif
#endif

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
#endif
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
    //--------------------------Swoole\Server--------------------------
    SW_SERVER_CB_onConnect,        //worker(event)
    SW_SERVER_CB_onReceive,        //worker(event)
    SW_SERVER_CB_onClose,          //worker(event)
    SW_SERVER_CB_onPacket,         //worker(event)
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
    //--------------------------Swoole\Http\Server----------------------
    SW_SERVER_CB_onRequest,        //http server
    //--------------------------Swoole\WebSocket\Server-----------------
    SW_SERVER_CB_onHandShake,      //worker(event)
    SW_SERVER_CB_onOpen,           //worker(event)
    SW_SERVER_CB_onMessage,        //worker(event)
    //--------------------------Buffer Event----------------------------
    SW_SERVER_CB_onBufferFull,     //worker(event)
    SW_SERVER_CB_onBufferEmpty,    //worker(event)
    //-------------------------------END--------------------------------
};

#define PHP_SERVER_CALLBACK_NUM             (SW_SERVER_CB_onBufferEmpty+1)

typedef struct
{
    zval *callbacks[PHP_SERVER_CALLBACK_NUM];
    zend_fcall_info_cache *caches[PHP_SERVER_CALLBACK_NUM];
#if PHP_MAJOR_VERSION >= 7
    zval _callbacks[PHP_SERVER_CALLBACK_NUM];
#endif
    zval *setting;
    swServer *serv;
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
    PHP_SWOOLE_FD_CHAN_PIPE,
#endif
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
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL))
#define php_swoole_array_length(array)      zend_hash_num_elements(Z_ARRVAL_P(array))

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;
extern zend_class_entry *swoole_server_port_class_entry_ptr;
extern zend_class_entry *swoole_exception_class_entry_ptr;

extern zval *php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
extern zend_fcall_info_cache *php_sw_server_caches[PHP_SERVER_CALLBACK_NUM];
#if PHP_MAJOR_VERSION >= 7
extern zval _php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
#endif

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
PHP_FUNCTION(swoole_unsupport_serialize);
PHP_FUNCTION(swoole_coroutine_create);
PHP_FUNCTION(swoole_coroutine_exec);

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

#ifdef HAVE_PCRE
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
#endif

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
PHP_FUNCTION(swoole_serialize);
PHP_FUNCTION(swoole_fast_serialize);
PHP_FUNCTION(swoole_unserialize);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_server_port_init(int module_number TSRMLS_DC);
void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
#ifdef SW_USE_PHPX
void swoole_runtime_init(int module_number TSRMLS_DC);
#endif
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_atomic_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
#ifdef SW_COROUTINE
void swoole_socket_coro_init(int module_number TSRMLS_DC);
void swoole_client_coro_init(int module_number TSRMLS_DC);
#ifdef SW_USE_REDIS
void swoole_redis_coro_init(int module_number TSRMLS_DC);
#endif
#ifdef SW_USE_POSTGRESQL
void swoole_postgresql_coro_init (int module_number TSRMLS_DC);
#endif
void swoole_mysql_coro_init(int module_number TSRMLS_DC);
void swoole_http_client_coro_init(int module_number TSRMLS_DC);
void swoole_coroutine_util_init(int module_number TSRMLS_DC);
#endif
void swoole_http_client_init(int module_number TSRMLS_DC);
#ifdef SW_USE_REDIS
void swoole_redis_init(int module_number TSRMLS_DC);
#endif
void swoole_redis_server_init(int module_number TSRMLS_DC);
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_process_pool_init(int module_number TSRMLS_DC);
void swoole_http_server_init(int module_number TSRMLS_DC);
#ifdef SW_USE_HTTP2
void swoole_http2_client_init(int module_number TSRMLS_DC);
#ifdef SW_COROUTINE
void swoole_http2_client_coro_init(int module_number TSRMLS_DC);
#endif
#endif
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);
void swoole_mysql_init(int module_number TSRMLS_DC);
void swoole_mmap_init(int module_number TSRMLS_DC);
void swoole_channel_init(int module_number TSRMLS_DC);
void swoole_ringqueue_init(int module_number TSRMLS_DC);
void swoole_msgqueue_init(int module_number TSRMLS_DC);
#ifdef SW_COROUTINE
void swoole_channel_coro_init(int module_number TSRMLS_DC);
#endif
void swoole_serialize_init(int module_number TSRMLS_DC);
void swoole_memory_pool_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_check_aio();
void php_swoole_at_shutdown(char *function);
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_check_timer(int interval);
long php_swoole_add_timer(int ms, zval *callback, zval *param, int persistent TSRMLS_DC);
void php_swoole_clear_all_timer();
void php_swoole_register_callback(swServer *serv);
void php_swoole_trace_check(void *arg);
void php_swoole_client_free(zval *object, swClient *cli TSRMLS_DC);
swClient* php_swoole_client_new(zval *object, char *host, int host_len, int port);
void php_swoole_client_check_setting(swClient *cli, zval *zset TSRMLS_DC);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset TSRMLS_DC);
#endif
void php_swoole_websocket_unpack(swString *data, zval *zframe TSRMLS_DC);
void php_swoole_sha1(const char *str, int _len, unsigned char *digest);
int php_swoole_client_isset_callback(zval *zobject, int type TSRMLS_DC);

int php_swoole_task_pack(swEventData *task, zval *data TSRMLS_DC);
zval* php_swoole_task_unpack(swEventData *task_result TSRMLS_DC);

static sw_inline void* swoole_get_object(zval *object)
{
    int handle = sw_get_object_handle(object);
    assert(handle < swoole_objects.size);
    return swoole_objects.array[handle];
}

static sw_inline void* swoole_get_property(zval *object, int property_id)
{
    int handle = sw_get_object_handle(object);
    if (handle >= swoole_objects.property_size[property_id])
    {
        return NULL;
    }
    return swoole_objects.property[property_id][handle];
}

void swoole_set_object(zval *object, void *ptr);
void swoole_set_property(zval *object, int property_id, void *ptr);
int swoole_convert_to_fd(zval *zsocket TSRMLS_DC);
int swoole_register_rshutdown_function(swCallback func, int push_back);
void swoole_call_rshutdown_function(void *arg);

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *swoole_convert_to_socket(int sock);
#endif

void php_swoole_server_before_start(swServer *serv, zval *zobject TSRMLS_DC);
void php_swoole_server_send_yield(swServer *serv, int fd, zval *zdata, zval *return_value);
void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onConnect(swServer *, swDataHead *);
int php_swoole_onReceive(swServer *, swEventData *);
int php_swoole_onPacket(swServer *, swEventData *);
void php_swoole_onClose(swServer *, swDataHead *);
void php_swoole_onBufferFull(swServer *, swDataHead *);
void php_swoole_onBufferEmpty(swServer *, swDataHead *);
int php_swoole_length_func(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
int php_swoole_dispatch_func(swServer *serv, swConnection *conn, swEventData *data);
int php_swoole_client_onPackage(swConnection *conn, char *data, uint32_t length);
void php_swoole_onTimeout(swTimer *timer, swTimer_node *tnode);
void php_swoole_onInterval(swTimer *timer, swTimer_node *tnode);

#if PHP_MAJOR_VERSION >= 7
PHPAPI zend_string* php_swoole_serialize(zval *zvalue);
PHPAPI int php_swoole_unserialize(void *buffer, size_t len, zval *return_value, zval *object_args, long flag);
#endif

#ifdef SW_COROUTINE
int php_coroutine_reactor_can_exit(swReactor *reactor);
#endif

static sw_inline zval* php_swoole_server_get_callback(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    if (port == NULL)
    {
        swWarn("invalid server_fd[%d].", server_fd);
        return NULL;
    }
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (!property)
    {
        return php_sw_server_callbacks[event_type];
    }
    zval *callback = property->callbacks[event_type];
    if (!callback)
    {
        return php_sw_server_callbacks[event_type];
    }
    else
    {
        return callback;
    }
}

#ifdef PHP_SWOOLE_ENABLE_FASTCALL
static sw_inline zend_fcall_info_cache* php_swoole_server_get_cache(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    swoole_server_port_property *property = (swoole_server_port_property *) port->ptr;
    if (!property)
    {
        return php_sw_server_caches[event_type];
    }
    zend_fcall_info_cache* cache = property->caches[event_type];
    if (!cache)
    {
        return php_sw_server_caches[event_type];
    }
    else
    {
        return cache;
    }
}
#endif

#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset TSRMLS_DC);
#endif

static sw_inline int php_swoole_is_callable(zval *callback TSRMLS_DC)
{
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return SW_FALSE;
    }
    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_WARNING, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_FALSE;
    }
    else
    {
        efree(func_name);
        return SW_TRUE;
    }
}

#define php_swoole_array_get_value(ht, str, v)     (sw_zend_hash_find(ht, str, sizeof(str), (void **) &v) == SUCCESS && !ZVAL_IS_NULL(v))
#define php_swoole_array_separate(arr)       zval *_new_##arr;\
    SW_MAKE_STD_ZVAL(_new_##arr);\
    array_init(_new_##arr);\
    sw_php_array_merge(Z_ARRVAL_P(_new_##arr), Z_ARRVAL_P(arr));\
    arr = _new_##arr;

static sw_inline zval* php_swoole_read_init_property(zend_class_entry *scope, zval *object, const char *p, size_t pl TSRMLS_DC)
{
    zval *property = sw_zend_read_property(scope, object, p, pl, 1 TSRMLS_CC);
    if (property == NULL || ZVAL_IS_NULL(property))
    {
        SW_MAKE_STD_ZVAL(property);
        array_init(property);
        zend_update_property(scope, object, p, pl, property TSRMLS_CC);
        sw_zval_ptr_dtor(&property);
        return sw_zend_read_property(scope, object, p, pl, 1 TSRMLS_CC);
    }
    else
    {
        return property;
    }
}

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_namespace;
    zend_bool use_shortname;
    zend_bool fast_serialize;
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

#ifndef ZEND_HASH_APPLY_PROTECTION
# define ZEND_HASH_APPLY_PROTECTION(p) 1
#endif

END_EXTERN_C()

#endif	/* PHP_SWOOLE_H */
