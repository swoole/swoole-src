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

#define PHP_SWOOLE_VERSION  "1.7.19-alpha"
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

#ifdef SW_ASYNC_MYSQL
#if defined(SW_HAVE_MYSQLI) && defined(SW_HAVE_MYSQLND)
#else
#error "Enable async_mysql support, But no mysqli or mysqlnd."
#undef SW_ASYNC_MYSQL
#endif
#endif

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, But no openssl library."
#endif
#endif

#include "php7_wrapper.h"

#define PHP_CLIENT_CALLBACK_NUM             4
//---------------------------------------------------
#define SW_CLIENT_CB_onConnect              0
#define SW_CLIENT_CB_onReceive              1
#define SW_CLIENT_CB_onClose                2
#define SW_CLIENT_CB_onError                3

#define SW_MAX_FIND_COUNT                   100    //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE           65535

#define PHP_SERVER_CALLBACK_NUM             17
//--------------------------------------------------------
#define SW_SERVER_CB_onStart                0 //Server start(master)
#define SW_SERVER_CB_onConnect              1 //accept new connection(worker)
#define SW_SERVER_CB_onReceive              2 //receive data(worker)
#define SW_SERVER_CB_onClose                3 //close tcp connection(worker)
#define SW_SERVER_CB_onShutdown             4 //Server sthudown(master)
#define SW_SERVER_CB_onTimer                5 //timer call(master)
#define SW_SERVER_CB_onWorkerStart          6 //Worker start(worker)
#define SW_SERVER_CB_onWorkerStop           7 //Worker shutdown(worker)
#define SW_SERVER_CB_onMasterConnect        8 //accept new connection(master)
#define SW_SERVER_CB_onMasterClose          9 //close tcp connection(master)
#define SW_SERVER_CB_onTask                 10 //new task(task_worker)
#define SW_SERVER_CB_onFinish               11 //async task finish(worker)
#define SW_SERVER_CB_onWorkerError          12 //worker exception(manager)
#define SW_SERVER_CB_onManagerStart         13
#define SW_SERVER_CB_onManagerStop          14
#define SW_SERVER_CB_onPipeMessage          15
#define SW_SERVER_CB_onPacket               16 //udp packet
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 9)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP))
#define php_swoole_array_length(array)      (Z_ARRVAL_P(array)->nNumOfElements)

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_lock_class_entry_ptr;
extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_table_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;

extern zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

extern HashTable php_sw_long_connections;

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

PHP_FUNCTION(swoole_server_create);
PHP_FUNCTION(swoole_server_set);
PHP_FUNCTION(swoole_server_start);
PHP_FUNCTION(swoole_server_stop);
PHP_FUNCTION(swoole_server_send);
PHP_FUNCTION(swoole_server_sendfile);
PHP_FUNCTION(swoole_server_close);
PHP_FUNCTION(swoole_server_on);
PHP_FUNCTION(swoole_server_handler);
PHP_FUNCTION(swoole_server_addlisten);
PHP_FUNCTION(swoole_server_addtimer);
PHP_FUNCTION(swoole_server_gettimer);
PHP_FUNCTION(swoole_server_task);
PHP_FUNCTION(swoole_server_taskwait);
PHP_FUNCTION(swoole_server_finish);
PHP_FUNCTION(swoole_server_reload);
PHP_FUNCTION(swoole_server_shutdown);
PHP_FUNCTION(swoole_server_heartbeat);
PHP_FUNCTION(swoole_connection_list);
PHP_FUNCTION(swoole_connection_info);

#ifdef HAVE_PCRE
PHP_METHOD(swoole_connection_iterator, count);
PHP_METHOD(swoole_connection_iterator, rewind);
PHP_METHOD(swoole_connection_iterator, next);
PHP_METHOD(swoole_connection_iterator, current);
PHP_METHOD(swoole_connection_iterator, key);
PHP_METHOD(swoole_connection_iterator, valid);
#endif

PHP_METHOD(swoole_server, sendmessage);
PHP_METHOD(swoole_server, addprocess);
PHP_METHOD(swoole_server, stats);
PHP_METHOD(swoole_server, bind);
PHP_METHOD(swoole_server, sendto);
PHP_METHOD(swoole_server, sendwait);
PHP_METHOD(swoole_server, exist);

PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_set);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_write);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);

PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_close);
PHP_FUNCTION(swoole_async_readfile);
PHP_FUNCTION(swoole_async_writefile);
PHP_FUNCTION(swoole_async_dns_lookup);
PHP_FUNCTION(swoole_async_set);

PHP_FUNCTION(swoole_timer_add);
PHP_FUNCTION(swoole_timer_del);
PHP_FUNCTION(swoole_timer_after);
PHP_FUNCTION(swoole_timer_tick);
PHP_FUNCTION(swoole_timer_clear);

PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
#endif

PHP_FUNCTION(swoole_client_select);

void swoole_destory_table(zend_resource *rsrc TSRMLS_DC);

void swoole_async_init(int module_number TSRMLS_DC);
void swoole_table_init(int module_number TSRMLS_DC);
void swoole_lock_init(int module_number TSRMLS_DC);
void swoole_atomic_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
void swoole_process_init(int module_number TSRMLS_DC);
void swoole_http_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);

int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC);

void php_swoole_check_reactor();
void php_swoole_event_init();
void php_swoole_event_wait();
void php_swoole_check_timer(int interval);
void php_swoole_register_callback(swServer *serv);

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

zval *php_swoole_get_recv_data(zval *,swEventData *req TSRMLS_DC);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_onClose(swServer *, int fd, int from_id);

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    zend_bool display_errors;
    zend_bool cli;
    key_t message_queue_key;
    uint32_t socket_buffer_size;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif	/* PHP_SWOOLE_H */
