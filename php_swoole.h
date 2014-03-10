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
  | license@php.net so we can mail you a copy immediately.               |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "Server.h"
#include "Client.h"

#define PHP_SWOOLE_VERSION  "1.6.12-alpha"

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

#pragma pack(4)
typedef struct {
	uint16_t port;
	uint16_t from_fd;
} php_swoole_udp_t;
#pragma pack()

extern zend_module_entry swoole_module_entry;
extern char php_sw_reactor_wait_onexit;

#define phpext_swoole_ptr &swoole_module_entry

#ifdef PHP_WIN32
#	define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_SWOOLE_API
#endif

#ifdef ZTS
#include "TSRM.h"
extern void ***sw_thread_ctx;
#endif
//#define SW_USE_PHP        1
#define SW_HANDLE_NUM
#define SW_CHECK_RETURN(s)  if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return

#ifdef SW_ASYNC_MYSQL
#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4 && defined(SW_HAVE_MYSQLI) && defined(SW_HAVE_MYSQLND)
#else
#error "Enable async_mysql support, But no mysqli or mysqlnd."
#undef SW_ASYNC_MYSQL
#endif
#endif

#define SW_RES_SERVER_NAME          "SwooleServer"
#define SW_RES_CLIENT_NAME          "SwooleClient"
#define SW_RES_LOCK_NAME            "SwooleLock"

#define PHP_CLIENT_CALLBACK_NUM             4
//---------------------------------------------------
#define SW_CLIENT_CB_onConnect              0
#define SW_CLIENT_CB_onReceive              1
#define SW_CLIENT_CB_onClose                2
#define SW_CLIENT_CB_onError                3

#define SW_MAX_FIND_COUNT                  100 //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE          65535

#define PHP_SERVER_CALLBACK_NUM             13
//---------------------------------------------------
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
//---------------------------------------------------------
#define SW_FLAG_KEEP                        (1u << 9)
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP))

#define SW_LONG_CONNECTION_KEY_LEN          64

extern int le_swoole_server;
extern int le_swoole_client;
extern int le_swoole_lock;

extern zend_class_entry *swoole_lock_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;

extern HashTable php_sw_reactor_callback;
extern HashTable php_sw_client_callback;
extern HashTable php_sw_timer_callback;
extern HashTable php_sw_long_connections;
extern HashTable php_sw_aio_callback;;

PHP_MINIT_FUNCTION(swoole);
PHP_MSHUTDOWN_FUNCTION(swoole);
PHP_RINIT_FUNCTION(swoole);
PHP_RSHUTDOWN_FUNCTION(swoole);
PHP_MINFO_FUNCTION(swoole);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_set_process_name);
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
PHP_FUNCTION(swoole_server_deltimer);
PHP_FUNCTION(swoole_server_task);
PHP_FUNCTION(swoole_server_taskwait);
PHP_FUNCTION(swoole_server_finish);
PHP_FUNCTION(swoole_server_reload);
PHP_FUNCTION(swoole_server_shutdown);
PHP_FUNCTION(swoole_server_heartbeat);
PHP_FUNCTION(swoole_connection_list);
PHP_FUNCTION(swoole_connection_info);

PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);

PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_readfile);
PHP_FUNCTION(swoole_async_writefile);

PHP_FUNCTION(swoole_timer_add);
PHP_FUNCTION(swoole_timer_del);

PHP_FUNCTION(swoole_strerror);

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock);
#endif

PHP_FUNCTION(swoole_client_select);

PHP_METHOD(swoole_client, __construct);
PHP_METHOD(swoole_client, connect);
PHP_METHOD(swoole_client, recv);
PHP_METHOD(swoole_client, send);
PHP_METHOD(swoole_client, close);
PHP_METHOD(swoole_client, on);

PHP_METHOD(swoole_lock, __construct);
PHP_METHOD(swoole_lock, lock);
PHP_METHOD(swoole_lock, trylock);
PHP_METHOD(swoole_lock, lock_read);
PHP_METHOD(swoole_lock, trylock_read);
PHP_METHOD(swoole_lock, unlock);

void swoole_destory_lock(zend_rsrc_list_entry *rsrc TSRMLS_DC);
void php_swoole_check_reactor();
void php_swoole_try_run_reactor();

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif

#endif	/* PHP_SWOOLE_H */
