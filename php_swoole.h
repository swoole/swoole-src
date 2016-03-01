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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

#define PHP_SWOOLE_VERSION  "1.8.2-rc2"
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
#define SWOOLE_OBJECT_MAX       1000000

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
    SW_CLIENT_CB_onConnect,
    SW_CLIENT_CB_onReceive,
    SW_CLIENT_CB_onClose,
    SW_CLIENT_CB_onError,
};
//--------------------------------------------------------
enum php_swoole_server_callback_type
{
    /**
     * port callback
     */
    SW_SERVER_CB_onConnect,        //accept new connection(worker)
    SW_SERVER_CB_onReceive,        //receive data(worker)
    SW_SERVER_CB_onClose,          //close tcp connection(worker)
    SW_SERVER_CB_onPacket,         //udp packet
    /**
     * server callback
     */
    SW_SERVER_CB_onStart,          //Server start(master)
    SW_SERVER_CB_onShutdown,       //Server sthudown(master)
    SW_SERVER_CB_onWorkerStart,    //Worker start(worker)
    SW_SERVER_CB_onWorkerStop,     //Worker shutdown(worker)
    SW_SERVER_CB_onTimer,
    SW_SERVER_CB_onTask,           //new task(task_worker)
    SW_SERVER_CB_onFinish,         //async task finish(worker)
    SW_SERVER_CB_onWorkerError,    //worker exception(manager)
    SW_SERVER_CB_onManagerStart,
    SW_SERVER_CB_onManagerStop,
    SW_SERVER_CB_onPipeMessage,
};

#define PHP_SERVER_CALLBACK_NUM             (SW_SERVER_CB_onPipeMessage+1)
#define PHP_SERVER_PORT_CALLBACK_NUM        (SW_SERVER_CB_onPacket+1)

typedef struct
{
    zval *callbacks[PHP_SERVER_PORT_CALLBACK_NUM];
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

extern zend_class_entry *swoole_lock_class_entry_ptr;
extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_http_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_table_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;
extern zend_class_entry *swoole_websocket_frame_class_entry_ptr;
extern zend_class_entry *swoole_server_port_class_entry_ptr;

extern zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

#define PHP_MEMORY_DEBUG  0

#if PHP_MEMORY_DEBUG
typedef struct
{
    int new_client;
    int free_client;
    int new_http_response;
    int new_http_request;
    int free_http_response;
    int free_http_request;
} php_vmstat_t;
extern php_vmstat_t php_vmstat;
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

//---------------------------------------------------------
//                  swoole_server
//---------------------------------------------------------
PHP_METHOD(swoole_server, __construct);
PHP_METHOD(swoole_server, set);
PHP_METHOD(swoole_server, on);
PHP_METHOD(swoole_server, listen);
PHP_METHOD(swoole_server, sendmessage);
PHP_METHOD(swoole_server, addprocess);
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
PHP_METHOD(swoole_server, task);
PHP_METHOD(swoole_server, taskwait);
PHP_METHOD(swoole_server, finish);
PHP_METHOD(swoole_server, reload);
PHP_METHOD(swoole_server, shutdown);
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
PHP_FUNCTION(swoole_timer_clear);

PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);
//---------------------------------------------------------
//                  swoole_mysql
//---------------------------------------------------------
#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
PHP_FUNCTION(swoole_mysql_query);
#endif

PHP_FUNCTION(swoole_client_select);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_server_port_init(int module_number TSRMLS_DC);
void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_atomic_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
#ifdef SW_ASYNC_HTTPCLIENT
void swoole_http_client_init(int module_number TSRMLS_DC);
#endif
#ifdef SW_USE_REDIS
void swoole_redis_init(int module_number TSRMLS_DC);
#endif
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_http_server_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);
void swoole_mysql_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_check_timer(int interval);
void php_swoole_register_callback(swServer *serv);
int php_swoole_set_callback(zval **array, int key, zval *cb TSRMLS_DC);
swClient* php_swoole_client_create_socket(zval *object, char *host, int host_len, int port);
zval* php_swoole_websocket_unpack(swString *data TSRMLS_DC);

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

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *swoole_convert_to_socket(int sock);
#endif

void php_swoole_server_before_start(swServer *serv, zval *zobject TSRMLS_DC);
zval *php_swoole_get_recv_data(zval *,swEventData *req TSRMLS_DC);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onConnect(swServer *serv, swDataHead *);
int php_swoole_onReceive(swServer *serv, swEventData *req);
void php_swoole_onClose(swServer *, swDataHead *);

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

#endif	/* PHP_SWOOLE_H */
