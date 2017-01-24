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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

#define PHP_SWOOLE_VERSION  "1.9.5"
#define PHP_SWOOLE_CHECK_CALLBACK

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

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
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{RETURN_FALSE;}return

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
#else
#ifdef SW_USE_HTTP2
#error "Enable http2 support, require --enable-openssl."
#endif
#endif

#ifdef SW_SOCKETS
#if PHP_VERSION_ID >= 50301 && (HAVE_SOCKETS || defined(COMPILE_DL_SOCKETS))
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#else
#error "Enable sockets support, require sockets extension."
#endif
#endif

#ifdef SW_USE_HTTP2
#if !defined(HAVE_NGHTTP2)
#error "Enable http2 support, require nghttp2 library."
#endif
#if !defined(HAVE_OPENSSL)
#error "Enable http2 support, require openssl library."
#endif
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
#if PHP_MAJOR_VERSION >= 7
    zval _callbacks[PHP_SERVER_CALLBACK_NUM];
#endif
    zval *setting;
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
};
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL))
#define php_swoole_array_length(array)      (Z_ARRVAL_P(array)->nNumOfElements)

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
#if PHP_MAJOR_VERSION >= 7
extern zval _php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
#endif

PHP_MINIT_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_cpu_num);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_get_local_ip);

//---------------------------------------------------------
//                  swoole_server
//---------------------------------------------------------
PHP_METHOD(swoole_server, __construct);
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
PHP_METHOD(swoole_server, finish);
PHP_METHOD(swoole_server, reload);
PHP_METHOD(swoole_server, shutdown);
PHP_METHOD(swoole_server, getLastError);
PHP_METHOD(swoole_server, stop);
PHP_METHOD(swoole_server, heartbeat);

PHP_METHOD(swoole_server, connection_list);
PHP_METHOD(swoole_server, connection_info);

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
PHP_FUNCTION(swoole_async_set);
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
PHP_FUNCTION(swoole_load_module);
PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_server_port_init(int module_number TSRMLS_DC);
void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_atomic_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
void swoole_http_client_init(int module_number TSRMLS_DC);
#ifdef SW_USE_REDIS
void swoole_redis_init(int module_number TSRMLS_DC);
#endif
void swoole_redis_server_init(int module_number TSRMLS_DC);
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_http_server_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);
void swoole_mysql_init(int module_number TSRMLS_DC);
void swoole_module_init(int module_number TSRMLS_DC);
void swoole_mmap_init(int module_number TSRMLS_DC);
void swoole_channel_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_check_timer(int interval);
void php_swoole_register_callback(swServer *serv);
void php_swoole_client_free(zval *object, swClient *cli TSRMLS_DC);
swClient* php_swoole_client_new(zval *object, char *host, int host_len, int port);
void php_swoole_client_check_setting(swClient *cli, zval *zset TSRMLS_DC);
zval* php_swoole_websocket_unpack(swString *data TSRMLS_DC);
void php_swoole_sha1(const char *str, int _len, unsigned char *digest);

int php_swoole_task_pack(swEventData *task, zval *data TSRMLS_DC);
zval* php_swoole_task_unpack(swEventData *task_result TSRMLS_DC);

static sw_inline void* swoole_get_object(zval *object)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int)Z_OBJ_HANDLE(*object);
#endif
    assert(handle < swoole_objects.size);
    return swoole_objects.array[handle];
}

static sw_inline void* swoole_get_property(zval *object, int property_id)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    if (handle >= swoole_objects.property_size[property_id])
    {
        return NULL;
    }
    return swoole_objects.property[property_id][handle];
}

void swoole_set_object(zval *object, void *ptr);
void swoole_set_property(zval *object, int property_id, void *ptr);
int swoole_convert_to_fd(zval *zsocket TSRMLS_DC);

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *swoole_convert_to_socket(int sock);
#endif

void php_swoole_server_before_start(swServer *serv, zval *zobject TSRMLS_DC);
void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onConnect(swServer *, swDataHead *);
int php_swoole_onReceive(swServer *, swEventData *);
void php_swoole_onClose(swServer *, swDataHead *);
void php_swoole_onBufferFull(swServer *, swDataHead *);
void php_swoole_onBufferEmpty(swServer *, swDataHead *);
int php_swoole_length_func(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);

static sw_inline zval* php_swoole_server_get_callback(swServer *serv, int server_fd, int event_type)
{
    swListenPort *port = serv->connection_list[server_fd].object;
    swoole_server_port_property *property = port->ptr;
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

#define php_swoole_array_get_value(ht, str, v)     (sw_zend_hash_find(ht, str, sizeof(str), (void **) &v) == SUCCESS && !ZVAL_IS_NULL(v))
#define php_swoole_array_separate(arr)       zval *_new_##arr;\
    SW_MAKE_STD_ZVAL(_new_##arr);\
    array_init(_new_##arr);\
    sw_php_array_merge(Z_ARRVAL_P(_new_##arr), Z_ARRVAL_P(arr));\
    arr = _new_##arr;

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_namespace;
    key_t message_queue_key;
    uint32_t socket_buffer_size;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif


#define SWOOLE_INIT_CLASS_ENTRY(ce, name, name_ns, methods) \
    if (SWOOLE_G(use_namespace)) { \
        INIT_CLASS_ENTRY(ce, name_ns, methods); \
    } else { \
        INIT_CLASS_ENTRY(ce, name, methods); \
    }

#define SWOOLE_CLASS_ALIAS(name, name_ns) \
    if (SWOOLE_G(use_namespace)) { \
        zend_register_class_alias(#name, name##_class_entry_ptr);\
    } else { \
        zend_register_class_alias(name_ns, name##_class_entry_ptr);\
    }

#endif	/* PHP_SWOOLE_H */
