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

/* $Id: swoole.c 2013-12-24 10:31:55Z tianfeng $ */

#include "php_swoole.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

HashTable php_sw_event_callback;
HashTable php_sw_timer_callback;
HashTable php_sw_client_callback;
HashTable php_sw_aio_callback;

#ifdef ZTS
void ***sw_thread_ctx;
#endif

static swEventData *sw_current_task;
static int php_swoole_task_id;
static int php_swoole_udp_from_id;
static int php_swoole_unix_dgram_fd;

extern sapi_module_struct sapi_module;

ZEND_DECLARE_MODULE_GLOBALS(swoole)

// arginfo server
// *_oo : for object style

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_create, 0, 0, 2)
	ZEND_ARG_INFO(0, serv_host)
	ZEND_ARG_INFO(0, serv_port)
	ZEND_ARG_INFO(0, serv_mode)
	ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, zset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, zset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_start, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_start_oo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, conn_fd)
	ZEND_ARG_INFO(0, send_data)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, conn_fd)
	ZEND_ARG_INFO(0, send_data)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, conn_fd)
	ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, conn_fd)
	ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_handler, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, ha_name)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_handler_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, ha_name)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, ha_name)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, ha_name)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addlisten, 0, 0, 4)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, host)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addlisten_oo, 0, 0, 3)
	ZEND_ARG_INFO(0, host)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addtimer, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addtimer_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_deltimer, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_deltimer_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

//function style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

//object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

//function style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, timeout)
	ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_taskwait_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, timeout)
	ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload_oo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_shutdown, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_shutdown_oo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat_oo, 0, 0, 1)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_info, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_info_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, from_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_list, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, zobject, swoole_server, 0)
	ZEND_ARG_INFO(0, start_fd)
	ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connection_list_oo, 0, 0, 2)
	ZEND_ARG_INFO(0, start_fd)
	ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

//arginfo event
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_add, 0, 0, 2)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_del, 0, 0, 1)
	ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_exit, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_wait, 0, 0, 0)
ZEND_END_ARG_INFO()

//arginfo timer
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_add, 0, 0, 2)
	ZEND_ARG_INFO(0, interval)
	ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_del, 0, 0, 1)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

//arginfo end

static int php_swoole_onReceive(swFactory *, swEventData *);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onConnect(swServer *, int fd, int from_id);
static void php_swoole_onClose(swServer *, int fd, int from_id);
static void php_swoole_onTimer(swServer *serv, int interval);
static void php_swoole_onWorkerStart(swServer *, int worker_id);
static void php_swoole_onWorkerStop(swServer *, int worker_id);
static int php_swoole_onTask(swServer *, swEventData *task);
static int php_swoole_onFinish(swServer *, swEventData *task);
static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code);

static void swoole_destory_server(zend_rsrc_list_entry *rsrc TSRMLS_DC);
static void swoole_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC);

static int php_swoole_task_finish(swServer *serv, char *data, int data_len TSRMLS_DC);
static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC);

#define SWOOLE_GET_SERVER(zobject, serv) zval **zserv;\
	if (zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_server"), (void **) &zserv) == FAILURE){ \
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have swoole server");\
	RETURN_FALSE;}\
	ZEND_FETCH_RESOURCE(serv, swServer *, zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);

#ifdef SW_ASYNC_MYSQL
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqli/mysqli_mysqlnd.h"
#include "ext/mysqli/php_mysqli_structs.h"
#endif

#include "zend_exceptions.h"

const zend_function_entry swoole_functions[] =
{
	PHP_FE(swoole_version, NULL)
	PHP_FE(swoole_cpu_num, NULL)
	/*------swoole_server-----*/
	PHP_FE(swoole_server_create, arginfo_swoole_server_create)
	PHP_FE(swoole_server_set, arginfo_swoole_server_set)
	PHP_FE(swoole_server_start, arginfo_swoole_server_start)
	PHP_FE(swoole_server_send, arginfo_swoole_server_send)
	PHP_FE(swoole_server_sendfile, arginfo_swoole_server_sendfile)
	PHP_FE(swoole_server_close, arginfo_swoole_server_close)
	PHP_FE(swoole_server_handler, arginfo_swoole_server_handler)
	PHP_FE(swoole_server_on, arginfo_swoole_server_on)
	PHP_FE(swoole_server_addlisten, arginfo_swoole_server_addlisten)

	PHP_FE(swoole_server_addtimer, arginfo_swoole_server_addtimer)
	PHP_FE(swoole_server_deltimer, arginfo_swoole_server_deltimer)
	PHP_FE(swoole_server_gettimer, NULL)

	PHP_FE(swoole_server_task, arginfo_swoole_server_task)
	PHP_FE(swoole_server_taskwait, arginfo_swoole_server_taskwait)
	PHP_FE(swoole_server_finish, arginfo_swoole_server_finish)
	PHP_FE(swoole_server_reload, arginfo_swoole_server_reload)
	PHP_FE(swoole_server_shutdown, arginfo_swoole_server_shutdown)
	PHP_FE(swoole_server_heartbeat, arginfo_swoole_server_heartbeat)
	PHP_FE(swoole_connection_info, arginfo_swoole_connection_info)
	PHP_FE(swoole_connection_list, arginfo_swoole_connection_list)
	/*------swoole_event-----*/
	PHP_FE(swoole_event_add, arginfo_swoole_event_add)
	PHP_FE(swoole_event_set, NULL)
	PHP_FE(swoole_event_del, arginfo_swoole_event_del)
	PHP_FE(swoole_event_exit, arginfo_swoole_event_exit)
	PHP_FE(swoole_event_wait, arginfo_swoole_event_wait)
	/*------swoole_timer-----*/
	PHP_FE(swoole_timer_add, arginfo_swoole_timer_add)
	PHP_FE(swoole_timer_del, arginfo_swoole_timer_del)
	/*------swoole_async_io------*/
	PHP_FE(swoole_async_set, NULL)
	PHP_FE(swoole_async_read, NULL)
	PHP_FE(swoole_async_write, NULL)
	PHP_FE(swoole_async_readfile, NULL)
	PHP_FE(swoole_async_writefile, NULL)
	PHP_FE(swoole_async_dns_lookup, NULL)
	/*------other-----*/
	PHP_FE(swoole_client_select, NULL)
	PHP_FE(swoole_set_process_name, NULL)
	PHP_FE(swoole_get_local_ip, NULL)
	PHP_FE(swoole_strerror, NULL)
	PHP_FE(swoole_errno, NULL)
#ifdef SW_ASYNC_MYSQL
	PHP_FE(swoole_get_mysqli_sock, NULL)
#endif
	PHP_FE_END /* Must be the last line in swoole_functions[] */
};

static zend_function_entry swoole_server_methods[] = {
	PHP_FALIAS(__construct, swoole_server_create, arginfo_swoole_server_create)
	PHP_FALIAS(set, swoole_server_set, arginfo_swoole_server_set_oo)
	PHP_FALIAS(start, swoole_server_start, arginfo_swoole_server_start_oo)
	PHP_FALIAS(send, swoole_server_send, arginfo_swoole_server_send_oo)
	PHP_FALIAS(sendfile, swoole_server_sendfile, arginfo_swoole_server_sendfile_oo)
	PHP_FALIAS(close, swoole_server_close, arginfo_swoole_server_close_oo)
	PHP_FALIAS(task, swoole_server_task, arginfo_swoole_server_task_oo)
	PHP_FALIAS(taskwait, swoole_server_taskwait, arginfo_swoole_server_taskwait_oo)
	PHP_FALIAS(finish, swoole_server_finish, arginfo_swoole_server_finish_oo)
	PHP_FALIAS(addlistener, swoole_server_addlisten, arginfo_swoole_server_addlisten_oo)
	PHP_FALIAS(addtimer, swoole_server_addtimer, arginfo_swoole_server_addtimer_oo)
	PHP_FALIAS(deltimer, swoole_server_deltimer, arginfo_swoole_server_deltimer_oo)
	PHP_FALIAS(gettimer, swoole_server_gettimer, NULL)
	PHP_FALIAS(reload, swoole_server_reload, arginfo_swoole_server_reload_oo)
	PHP_FALIAS(shutdown, swoole_server_shutdown, arginfo_swoole_server_shutdown_oo)
	PHP_FALIAS(hbcheck, swoole_server_heartbeat, arginfo_swoole_server_heartbeat_oo)
	PHP_FALIAS(heartbeat, swoole_server_heartbeat, arginfo_swoole_server_heartbeat_oo)
	PHP_FALIAS(handler, swoole_server_handler, arginfo_swoole_server_handler_oo)
	PHP_FALIAS(on, swoole_server_on, arginfo_swoole_server_on_oo)
	PHP_FALIAS(connection_info, swoole_connection_info, arginfo_swoole_connection_info_oo)
	PHP_FALIAS(connection_list, swoole_connection_list, arginfo_swoole_connection_list_oo)
	PHP_ME(swoole_server, stats, NULL, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

const zend_function_entry swoole_client_methods[] =
{
	PHP_ME(swoole_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(swoole_client, connect, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, recv, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, send, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, sendfile, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, close, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, on, NULL, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

const zend_function_entry swoole_process_methods[] =
{
	PHP_ME(swoole_process, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(swoole_process, wait, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(swoole_process, kill, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	PHP_ME(swoole_process, start, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_process, write, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_process, read, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_process, exit, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_process, exec, NULL, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

const zend_function_entry swoole_buffer_methods[] =
{
    PHP_ME(swoole_buffer, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_buffer, substr, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_buffer, read, substr, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, write, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, append, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, expand, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, clear, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_table_methods[] =
{
    PHP_ME(swoole_table, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_table, column, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, create, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, add, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, get, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, lock, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_table, unlock, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_lock_methods[] =
{
	PHP_ME(swoole_lock, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(swoole_lock, lock, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_lock, trylock, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_lock, lock_read, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_lock, trylock_read, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_lock, unlock, NULL, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

int le_swoole_server;
int le_swoole_client;
int le_swoole_lock;
int le_swoole_process;
int le_swoole_table;
int le_swoole_buffer;

zend_class_entry swoole_lock_ce;
zend_class_entry *swoole_lock_class_entry_ptr;

zend_class_entry swoole_client_ce;
zend_class_entry *swoole_client_class_entry_ptr;

zend_class_entry swoole_process_ce;
zend_class_entry *swoole_process_class_entry_ptr;

zend_class_entry swoole_server_ce;
zend_class_entry *swoole_server_class_entry_ptr;

zend_class_entry swoole_table_ce;
zend_class_entry *swoole_table_class_entry_ptr;

zend_class_entry swoole_buffer_ce;
zend_class_entry *swoole_buffer_class_entry_ptr;

zend_module_entry swoole_module_entry =
{
#if ZEND_MODULE_API_NO >= 20050922
	STANDARD_MODULE_HEADER_EX,
	NULL,
	NULL,
#else
	STANDARD_MODULE_HEADER,
#endif
	"swoole",
	swoole_functions,
	PHP_MINIT(swoole),
	PHP_MSHUTDOWN(swoole),
	PHP_RINIT(swoole), //RINIT
	PHP_RSHUTDOWN(swoole), //RSHUTDOWN
	PHP_MINFO(swoole),
    PHP_SWOOLE_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SWOOLE
ZEND_GET_MODULE(swoole)
#endif

/* {{{ PHP_INI
 */

PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("swoole.task_worker_num", "0", PHP_INI_ALL, OnUpdateLong, task_worker_num, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("swoole.task_ipc_mode", "0", PHP_INI_ALL, OnUpdateString, task_ipc_mode, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("swoole.task_auto_start", "0", PHP_INI_ALL, OnUpdateString, task_auto_start, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("swoole.message_queue_key", "0", PHP_INI_ALL, OnUpdateString, message_queue_key, zend_swoole_globals, swoole_globals)
/**
 * Unix socket buffer size
 */
STD_PHP_INI_ENTRY("swoole.unixsock_buffer_size", "8388608", PHP_INI_ALL, OnUpdateLong, unixsock_buffer_size, zend_swoole_globals, swoole_globals)
PHP_INI_END()

static void php_swoole_init_globals(zend_swoole_globals *swoole_globals)
{
	swoole_globals->task_worker_num = 0;
	swoole_globals->task_ipc_mode = 0;
	swoole_globals->unixsock_buffer_size = SW_UNSOCK_BUFSIZE;
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(swoole)
{
	ZEND_INIT_MODULE_GLOBALS(swoole, php_swoole_init_globals, NULL);
	REGISTER_INI_ENTRIES();

	le_swoole_server = zend_register_list_destructors_ex(swoole_destory_server, NULL, SW_RES_SERVER_NAME, module_number);
	le_swoole_client = zend_register_list_destructors_ex(swoole_destory_client, NULL, SW_RES_CLIENT_NAME, module_number);
	le_swoole_lock = zend_register_list_destructors_ex(swoole_destory_lock, NULL, SW_RES_LOCK_NAME, module_number);
	le_swoole_process = zend_register_list_destructors_ex(swoole_destory_process, NULL, SW_RES_PROCESS_NAME, module_number);
	le_swoole_buffer = zend_register_list_destructors_ex(swoole_destory_buffer, NULL, SW_RES_BUFFER_NAME, module_number);
	le_swoole_table = zend_register_list_destructors_ex(swoole_destory_table, NULL, SW_RES_TABLE_NAME, module_number);

	/**
	 * mode type
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_BASE", SW_MODE_SINGLE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_THREAD", SW_MODE_THREAD, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", SW_MODE_PROCESS, CONST_CS | CONST_PERSISTENT);

	/**
	 * ipc mode
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_IPC_UNSOCK", SW_IPC_UNSOCK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_IPC_MSGQUEUE", SW_IPC_MSGQUEUE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_IPC_CHANNEL", SW_IPC_CHANNEL, CONST_CS | CONST_PERSISTENT);

	/**
	 * socket type
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
	/**
	 * simple api
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_UNIX_STREAM", SW_SOCK_UNIX_STREAM, CONST_CS | CONST_PERSISTENT);
	/**
	 * Lock type
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", SW_RWLOCK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_FILELOCK", SW_FILELOCK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", SW_MUTEX, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SEM", SW_SEM, CONST_CS | CONST_PERSISTENT);

#ifdef HAVE_SPINLOCK
	REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", SW_SPINLOCK, CONST_CS | CONST_PERSISTENT);
#endif
	/**
	 * simple api
	 */
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_SYNC", SW_SOCK_SYNC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_ASYNC", SW_SOCK_ASYNC, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_SYNC", SW_FLAG_SYNC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_ASYNC", SW_FLAG_ASYNC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_KEEP", SW_FLAG_KEEP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SSL", SW_SOCK_SSL, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_EVENT_READ", SW_EVENT_READ, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_EVENT_WRITE", SW_EVENT_WRITE, CONST_CS | CONST_PERSISTENT);

    REGISTER_STRINGL_CONSTANT("SWOOLE_VERSION", PHP_SWOOLE_VERSION, sizeof(PHP_SWOOLE_VERSION) - 1, CONST_CS | CONST_PERSISTENT);

	INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", swoole_client_methods);
	swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);

	zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_server_ce, "swoole_server", swoole_server_methods);
	swoole_server_class_entry_ptr = zend_register_internal_class(&swoole_server_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_lock_ce, "swoole_lock", swoole_lock_methods);
	swoole_lock_class_entry_ptr = zend_register_internal_class(&swoole_lock_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_process_ce, "swoole_process", swoole_process_methods);
	swoole_process_class_entry_ptr = zend_register_internal_class(&swoole_process_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_buffer_ce, "swoole_buffer", swoole_buffer_methods);
	swoole_buffer_class_entry_ptr = zend_register_internal_class(&swoole_buffer_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_table_ce, "swoole_table", swoole_table_methods);
	swoole_table_class_entry_ptr = zend_register_internal_class(&swoole_table_ce TSRMLS_CC);

	zend_hash_init(&php_sw_long_connections, 16, NULL, ZVAL_PTR_DTOR, 1);

	//swoole init
	swoole_init();

	swoole_async_init(module_number TSRMLS_CC);
	swoole_table_init(module_number TSRMLS_CC);

	if (SWOOLE_G(unixsock_buffer_size) > 0)
	{
		SwooleG.unixsock_buffer_size = SWOOLE_G(unixsock_buffer_size);
	}
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(swoole)
{
	swoole_clean();
	if (php_sw_in_client && SwooleG.main_reactor)
	{
	    sw_free(SwooleG.main_reactor);
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(swoole)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "swoole support", "enabled");
	php_info_print_table_row(2, "Version", PHP_SWOOLE_VERSION);
	php_info_print_table_row(2, "Author", "tianfeng.han[email: mikan.tenny@gmail.com]");

#ifdef HAVE_EPOLL
	php_info_print_table_row(2, "epoll", "enabled");
#endif
#ifdef HAVE_EVENTFD
    php_info_print_table_row(2, "event_fd", "enabled");
#endif
#ifdef HAVE_KQUEUE
    php_info_print_table_row(2, "kqueue", "enabled");
#endif
#ifdef HAVE_TIMERFD
    php_info_print_table_row(2, "timerfd", "enabled");
#endif
#ifdef SW_USE_ACCEPT4
    php_info_print_table_row(2, "accept4", "enabled");
#endif
#ifdef HAVE_CPU_AFFINITY
    php_info_print_table_row(2, "cpu affinity", "enabled");
#endif
#ifdef HAVE_SPINLOCK
    php_info_print_table_row(2, "spinlock", "enabled");
#endif
#ifdef SW_ASYNC_MYSQL
    php_info_print_table_row(2, "async mysql", "enabled");
#endif
#ifdef SW_SOCKETS
    php_info_print_table_row(2, "sockets", "enabled");
#endif
#ifdef SW_USE_OPENSSL
    php_info_print_table_row(2, "openssl", "enabled");
#endif
#ifdef SW_USE_RINGBUFFER
    php_info_print_table_row(2, "ringbuffer", "enabled");
#endif
#ifdef HAVE_LINUX_AIO
    php_info_print_table_row(2, "Linux Native AIO", "enabled");
#endif
#ifdef HAVE_GCC_AIO
    php_info_print_table_row(2, "Gcc AIO", "enabled");
#endif

    php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

PHP_RINIT_FUNCTION(swoole)
{
	//swoole_event_add
	zend_hash_init(&php_sw_event_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//swoole_client::on
	zend_hash_init(&php_sw_client_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//swoole_timer_add
	zend_hash_init(&php_sw_timer_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//swoole_aio
	zend_hash_init(&php_sw_aio_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//running
	SwooleG.running = 1;
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(swoole)
{
	zend_hash_destroy(&php_sw_event_callback);
	zend_hash_destroy(&php_sw_client_callback);
	zend_hash_destroy(&php_sw_timer_callback);
	zend_hash_destroy(&php_sw_aio_callback);

	int i;
	for(i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(php_sw_callback[i] != NULL)
		{
			zval_dtor(php_sw_callback[i]);
			efree(php_sw_callback[i]);
		}
	}
	php_sw_reactor_wait_onexit = 0;
	return SUCCESS;
}

static void swoole_destory_server(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	SwooleG.running = 0;
	swServer *serv = (swServer *) rsrc->ptr;
	if (serv != NULL)
	{
		swServer_shutdown(serv);
	}
}

static void swoole_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	swClient *cli = (swClient *) rsrc->ptr;
	if (cli->keep == 0)
	{
		if (cli->connection.fd != 0)
		{
			cli->close(cli);
		}
		efree(cli);
	}
}

PHP_FUNCTION(swoole_version)
{
	char swoole_version[32] = {0};
	snprintf(swoole_version, sizeof(PHP_SWOOLE_VERSION), "%s", PHP_SWOOLE_VERSION);
    RETURN_STRING(swoole_version, 1);
}

PHP_FUNCTION(swoole_cpu_num)
{
    long cpu_num = 1;
    cpu_num = sysconf(_SC_NPROCESSORS_CONF);
    if(cpu_num < 1)
    {
        cpu_num = 1;
    }
    RETURN_LONG(cpu_num);
}
#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock)
{
	MY_MYSQL *mysql;
	zval *mysql_link;
	int sock;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &mysql_link) == FAILURE)
	{
		return;
	}
	MYSQLI_FETCH_RESOURCE_CONN(mysql, &mysql_link, MYSQLI_STATUS_VALID);

	php_stream *stream;

#if PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 4
	stream = mysql->mysql->data->net->data->m.get_stream(mysql->mysql->data->net TSRMLS_CC);
#else
	stream = mysql->mysql->data->net->stream;
#endif

	if (SUCCESS != php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&sock, 1)
			&& sock >= 0)
	{
		RETURN_FALSE;
	}
	else
	{
		RETURN_LONG(sock);
	}
}
#endif

PHP_FUNCTION(swoole_server_create)
{
	int host_len = 0;
	char *serv_host;
	long sock_type = SW_SOCK_TCP;
	long serv_port;
	long serv_mode = SW_MODE_PROCESS;

	//only cli env
	if (strcasecmp("cli", sapi_module.name) != 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "swoole_server must run at php_cli environment.");
		RETURN_FALSE;
	}

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is already running. Unable to create swoole_server.");
		RETURN_FALSE;
	}

	swServer *serv = sw_malloc(sizeof(swServer));
	swServer_init(serv);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|ll", &serv_host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
	{
		return;
	}

	if (serv_mode == SW_MODE_THREAD || serv_mode == SW_MODE_BASE)
	{
		serv_mode = SW_MODE_SINGLE;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "PHP can not running at multi-threading. Reset mode to SWOOLE_MODE_BASE");
	}

	serv->factory_mode = serv_mode;
	swTrace("Create swoole_server host=%s, port=%ld, mode=%d, type=%d", serv_host, serv_port, serv->factory_mode, sock_type);

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	bzero(php_sw_callback, sizeof(zval*) * PHP_SERVER_CALLBACK_NUM);

	if (swServer_addListener(serv, sock_type, serv_host, serv_port) < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "add listener failed.");
		return;
	}
	if (!getThis())
	{
		object_init_ex(return_value, swoole_server_class_entry_ptr);
		getThis() = return_value;
	}
	zval *zres;
	MAKE_STD_ZVAL(zres);
	ZEND_REGISTER_RESOURCE(zres, serv, le_swoole_server);
	zend_update_property(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("_server"), zres TSRMLS_CC);
	zval_ptr_dtor(&zres);
}

PHP_METHOD(swoole_server, stats)
{
    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }
    array_init(return_value);
    add_assoc_long_ex(return_value, SW_STRL("start_time"), SwooleStats->start_time);
    add_assoc_long_ex(return_value, SW_STRL("connection_num"), SwooleStats->connection_num);
    add_assoc_long_ex(return_value, SW_STRL("accept_count"), SwooleStats->accept_count);
    add_assoc_long_ex(return_value, SW_STRL("close_count"), SwooleStats->close_count);
}

PHP_FUNCTION(swoole_server_set)
{
	zval *zset = NULL;
	zval *zobject = getThis();
	HashTable *vht;
	swServer *serv;
	zval **v;
	double timeout;

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server_set now.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oa", &zobject, swoole_server_class_entry_ptr, &zset) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &zset) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	vht = Z_ARRVAL_P(zset);

	//timeout
	if (zend_hash_find(vht, ZEND_STRS("timeout"), (void **)&v) == SUCCESS)
	{
		convert_to_double(*v);
		timeout = Z_DVAL_PP(v);
		serv->timeout_sec = (int)timeout;
		serv->timeout_usec = (int)((timeout*1000*1000) - (serv->timeout_sec*1000*1000));
	}
    //daemonize
    if (zend_hash_find(vht, ZEND_STRS("daemonize"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->daemonize = (int) Z_LVAL_PP(v);
    }
    //backlog
    if (zend_hash_find(vht, ZEND_STRS("backlog"), (void **) &v) == SUCCESS)
    {
        serv->backlog = (int) Z_LVAL_PP(v);
    }
	//poll_thread_num
	if (zend_hash_find(vht, ZEND_STRS("reactor_num"), (void **) &v) == SUCCESS
			|| zend_hash_find(vht, ZEND_STRS("poll_thread_num"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->reactor_num = (int) Z_LVAL_PP(v);
	}
	//writer_num
	if (zend_hash_find(vht, ZEND_STRS("writer_num"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->writer_num = (int)Z_LVAL_PP(v);
	}
	//worker_num
	if (zend_hash_find(vht, ZEND_STRS("worker_num"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->worker_num = (int)Z_LVAL_PP(v);
	}
	//task_worker_num
	if (zend_hash_find(vht, ZEND_STRS("task_worker_num"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		SwooleG.task_worker_num = (int)Z_LVAL_PP(v);
	}
	if (zend_hash_find(vht, ZEND_STRS("task_ipc_mode"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		SwooleG.task_ipc_mode = (int)Z_LVAL_PP(v);
	}
	//max_conn
	if (zend_hash_find(vht, ZEND_STRS("max_conn"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->max_conn = (int)Z_LVAL_PP(v);
	}
    //max_request
    if (zend_hash_find(vht, ZEND_STRS("max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->max_request = (int) Z_LVAL_PP(v);
    }
    //task_max_request
    if (zend_hash_find(vht, ZEND_STRS("task_max_request"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->task_max_request = (int) Z_LVAL_PP(v);
    }
	//cpu affinity
	if (zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_cpu_affinity = (uint8_t) Z_LVAL_PP(v);
	}
	//tcp_nodelay
	if (zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_tcp_nodelay = (uint8_t) Z_LVAL_PP(v);
	}
	//tcp_defer_accept
	if (zend_hash_find(vht, ZEND_STRS("tcp_defer_accept"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->tcp_defer_accept = (uint8_t) Z_LVAL_PP(v);
	}
	//socket linger
	if (zend_hash_find(vht, ZEND_STRS("tcp_socket_linger"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->tcp_socket_linger = (uint8_t) Z_LVAL_PP(v);
	}
	//tcp_keepalive
	if (zend_hash_find(vht, ZEND_STRS("open_tcp_keepalive"), (void **)&v) == SUCCESS)
	{
		serv->open_tcp_keepalive = (uint8_t) Z_LVAL_PP(v);
	}
	//buffer: check eof
	if (zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_eof_check = (uint8_t) Z_LVAL_PP(v);
	}
	//package eof
	if (zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &v) == SUCCESS
			|| zend_hash_find(vht, ZEND_STRS("data_eof"), (void **) &v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->package_eof_len = Z_STRLEN_PP(v);
		if (serv->package_eof_len > SW_DATA_EOF_MAXLEN)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
			RETURN_FALSE;
		}
		bzero(serv->package_eof, SW_DATA_EOF_MAXLEN);
		memcpy(serv->package_eof, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
	}
	//tcp_keepidle
	if (zend_hash_find(vht, ZEND_STRS("tcp_keepidle"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->tcp_keepidle = (uint16_t)Z_LVAL_PP(v);
	}
	//tcp_keepinterval
	if (zend_hash_find(vht, ZEND_STRS("tcp_keepinterval"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->tcp_keepinterval = (uint16_t)Z_LVAL_PP(v);
	}
	//tcp_keepcount
	if (zend_hash_find(vht, ZEND_STRS("tcp_keepcount"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->tcp_keepcount = (uint16_t)Z_LVAL_PP(v);
	}
	//dispatch_mode
	if (zend_hash_find(vht, ZEND_STRS("dispatch_mode"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->dispatch_mode = (int)Z_LVAL_PP(v);
	}

	//open_dispatch_key
	if (zend_hash_find(vht, ZEND_STRS("open_dispatch_key"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_dispatch_key = (int)Z_LVAL_PP(v);
	}

	if (zend_hash_find(vht, ZEND_STRS("dispatch_key_type"), (void **)&v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->dispatch_key_type = Z_STRVAL_PP(v)[0];
		serv->dispatch_key_size = swoole_type_size(serv->dispatch_key_type);

		if (serv->dispatch_key_size == 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow dispatch_key_type, see pack(). Link: http://php.net/pack");
			RETURN_FALSE;
		}
	}

	if (zend_hash_find(vht, ZEND_STRS("dispatch_key_offset"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->dispatch_key_offset = (uint16_t) Z_LVAL_PP(v);
	}

	//log_file
	if (zend_hash_find(vht, ZEND_STRS("log_file"), (void **)&v) == SUCCESS)
	{
		convert_to_string(*v);
		if (Z_STRLEN_PP(v) > SW_LOG_FILENAME)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "log_file name to long");
			RETURN_FALSE;
		}
		memcpy(serv->log_file, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
	}
	//heartbeat_check_interval
	if (zend_hash_find(vht, ZEND_STRS("heartbeat_check_interval"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->heartbeat_check_interval = (int) Z_LVAL_PP(v);
	}
	//heartbeat idle time
    if (zend_hash_find(vht, ZEND_STRS("heartbeat_idle_time"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->heartbeat_idle_time = (int) Z_LVAL_PP(v);

        if (serv->heartbeat_check_interval > serv->heartbeat_idle_time)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "heartbeat_idle_time must be greater than heartbeat_check_interval.");
            serv->heartbeat_check_interval = serv->heartbeat_idle_time;
        }
    }
    else if (serv->heartbeat_check_interval > 0)
    {
        serv->heartbeat_idle_time = serv->heartbeat_check_interval;
    }
	//heartbeat_ping
	if (zend_hash_find(vht, ZEND_STRS("heartbeat_ping"), (void **) &v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->heartbeat_ping_length = Z_STRLEN_PP(v);
		if (serv->heartbeat_ping_length > SW_HEARTBEAT_PING_LEN)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat ping package too long");
			RETURN_FALSE;
		}
		memcpy(serv->heartbeat_ping, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
	}
	//heartbeat_pong
	if (zend_hash_find(vht, ZEND_STRS("heartbeat_pong"), (void **) &v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->heartbeat_pong_length = Z_STRLEN_PP(v);
		if (serv->heartbeat_pong_length > SW_HEARTBEAT_PING_LEN)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "heartbeat pong package too long");
			RETURN_FALSE;
		}
		memcpy(serv->heartbeat_pong, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
	}
	//open length check
	if (zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_length_check = (uint8_t)Z_LVAL_PP(v);
	}
	//package length size
	if (zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **)&v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->package_length_type = Z_STRVAL_PP(v)[0];
		serv->package_length_size = swoole_type_size(serv->package_length_type);

		if (serv->package_length_size == 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
			RETURN_FALSE;
		}
	}
	//package length offset
	if (zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->package_length_offset = (int)Z_LVAL_PP(v);
	}
	//package body start
	if (zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &v) == SUCCESS
			|| zend_hash_find(vht, ZEND_STRS("package_body_start"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->package_body_offset = (int) Z_LVAL_PP(v);
	}
	/**
	 * package max length
	 */
	if (zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->package_max_length = (int) Z_LVAL_PP(v);
	}
    /**
     * buffer input size
     */
    if (zend_hash_find(vht, ZEND_STRS("buffer_input_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        serv->buffer_input_size = (int) Z_LVAL_PP(v);
    }
	/**
	 * buffer output size
	 */
	if (zend_hash_find(vht, ZEND_STRS("buffer_output_size"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->buffer_output_size = (int) Z_LVAL_PP(v);
	}
	//ipc mode
	if (zend_hash_find(vht, ZEND_STRS("ipc_mode"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->ipc_mode = (int) Z_LVAL_PP(v);
	}
	//message queue key
	if (zend_hash_find(vht, ZEND_STRS("message_queue_key"), (void **) &v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->message_queue_key = (int) Z_LVAL_PP(v);
	}

#ifdef SW_USE_OPENSSL
	if (zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->ssl_cert_file = strdup(Z_STRVAL_PP(v));
		if (access(serv->ssl_cert_file, R_OK) < 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl cert file[%s] not found.", serv->ssl_cert_file);
			return;
		}
		serv->open_ssl = 1;
	}
	if (zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &v) == SUCCESS)
	{
		convert_to_string(*v);
		serv->ssl_key_file = strdup(Z_STRVAL_PP(v));
		if (access(serv->ssl_key_file, R_OK) < 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl key file[%s] not found.", serv->ssl_key_file);
			return;
		}
	}
	if (serv->open_ssl && !serv->ssl_key_file)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ssl require key file.");
		return;
	}
#endif

	zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zset TSRMLS_CC);
	RETURN_TRUE;
}

static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC)
{

#ifdef PHP_SWOOLE_CHECK_CALLBACK
	char *func_name = NULL;
	if (!zend_is_callable(cb, 0, &func_name TSRMLS_CC))
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
		efree(func_name);
		return SW_ERR;
	}
	efree(func_name);
#endif

	//zval_add_ref(&cb);
	php_sw_callback[key] = emalloc(sizeof(zval));
	if(php_sw_callback[key] == NULL)
	{
		return SW_ERR;
	}

	*(php_sw_callback[key]) = *cb;
	zval_copy_ctor(php_sw_callback[key]);

	return SW_OK;
}

PHP_FUNCTION(swoole_server_handler)
{
	zval *zobject = getThis();
	char *ha_name = NULL;
	int len, i;
	int ret = -1;
	swServer *serv;
	zval *cb;

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osz", &zobject, swoole_server_class_entry_ptr, &ha_name, &len, &cb) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &ha_name, &len, &cb) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	//必须与define顺序一致
	char *callback[PHP_SERVER_CALLBACK_NUM] = {
			"onStart",
			"onConnect",
			"onReceive",
			"onClose",
			"onShutdown",
			"onTimer",
			"onWorkerStart",
			"onWorkerStop",
			"onMasterConnect",
			"onMasterClose",
			"onTask",
			"onFinish",
			"onWorkerError",
			"onManagerStart",
			"onManagerStop",
	};
	for (i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(strncasecmp(callback[i], ha_name, len) == 0)
		{
			ret = php_swoole_set_callback(i, cb TSRMLS_CC);
			break;
		}
	}
	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unknown event types[%s]", ha_name);
	}
	SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_on)
{
	zval *zobject = getThis();
	char *ha_name = NULL;
	int len, i;
	int ret = -1;
	swServer *serv;
	zval *cb;

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osz", &zobject, swoole_server_class_entry_ptr, &ha_name, &len, &cb) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &ha_name, &len, &cb) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	//必须与define顺序一致
	char *callback[PHP_SERVER_CALLBACK_NUM] = {
			"start",
			"connect",
			"receive",
			"close",
			"shutdown",
			"timer",
			"workerStart",
			"workerStop",
			"masterConnect",
			"masterClose",
			"task",
			"finish",
			"workerError",
			"managerStart",
			"managerStop",
	};

	for (i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(strncasecmp(callback[i], ha_name, len) == 0)
		{
			ret = php_swoole_set_callback(i, cb TSRMLS_CC);
			break;
		}
	}
	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unknown event types[%s]", ha_name);
	}
	SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_close)
{
	zval *zobject = getThis();
	swServer *serv;
	swEvent ev;
	zval *fd;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oz", &zobject, swoole_server_class_entry_ptr, &fd) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &fd) == FAILURE)
		{
			return;
		}
	}
	convert_to_long(fd);

	SWOOLE_GET_SERVER(zobject, serv);
	ev.fd = Z_LVAL_P(fd);

	/**
	 * Server refused to take the initiative
	 */
	ev.type = SW_CLOSE_INITIATIVE;

	//Master can't execute it
	if (swIsMaster())
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Can not close connection in master process.");
		RETURN_FALSE;
	}

	if (serv->factory.end(&serv->factory, &ev) >= 0)
	{
		RETVAL_TRUE;
	}
	else
	{
	    RETVAL_FALSE;
	}

	if (serv->onClose != NULL)
	{
	    serv->onClose(serv, ev.fd, ev.from_id);
	}
}

PHP_FUNCTION(swoole_server_reload)
{
	zval *zobject = getThis();
	swServer *serv;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	SW_CHECK_RETURN(swServer_reload(serv));
}

PHP_FUNCTION(swoole_server_heartbeat)
{
	zval *zobject = getThis();
	swServer *serv;
	swEvent ev;
	zend_bool close_connection = 0;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|b", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	else
	{
	    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &zobject, swoole_server_class_entry_ptr) == FAILURE)
        {
            return;
        }
	}
	SWOOLE_GET_SERVER(zobject, serv);

    if (serv->heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int serv_max_fd = swServer_get_maxfd(serv);
    int serv_min_fd = swServer_get_minfd(serv);

    array_init(return_value);

    int fd;
    int checktime = (int) SwooleGS->now - serv->heartbeat_idle_time;

    ev.type = SW_CLOSE_INITIATIVE;

    for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
    {
        swTrace("heartbeat check fd=%d", fd);
        if (1 == serv->connection_list[fd].active && (serv->connection_list[fd].last_time < checktime))
        {
            /**
             * Close the connection
             */
            if (close_connection)
            {
                ev.fd = fd;
                serv->factory.end(&serv->factory, &ev);
                if (serv->onClose != NULL)
                {
                    serv->onClose(serv, ev.fd, ev.from_id);
                }
            }
            add_next_index_long(return_value, fd);
        }
    }
}

PHP_FUNCTION(swoole_server_shutdown)
{
	zval *zobject = getThis();
	swServer *serv;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	if (kill(SwooleGS->master_pid, SIGTERM) < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "shutdown failed. kill -SIGTERM master_pid[%d] fail. Error: %s[%d]", SwooleGS->master_pid, strerror(errno), errno);
		RETURN_FALSE;
	}
	else
	{
		RETURN_TRUE;
	}
}

PHP_FUNCTION(swoole_connection_info)
{
	zval *zobject = getThis();
	swServer *serv;
	long fd = 0;
	long from_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol|l", &zobject, swoole_server_class_entry_ptr, &fd, &from_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &fd, &from_id) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	swConnection *conn = swServer_connection_get(serv, fd);

	//It's udp
	if (conn == NULL)
	{
		array_init(return_value);
		php_swoole_udp_t udp_info;
		if (from_id < 0)
		{
			from_id = php_swoole_udp_from_id;
		}
		memcpy(&udp_info, &from_id, sizeof(udp_info));

		swConnection *from_sock = swServer_connection_get(serv, udp_info.from_fd);
		struct in_addr sin_addr;
		sin_addr.s_addr = fd;
		if (from_sock != NULL)
		{
			add_assoc_long(return_value, "from_fd", udp_info.from_fd);
			add_assoc_long(return_value, "from_port",  from_sock->addr.sin_port);
		}
		if (from_id !=0 )
		{
			add_assoc_long(return_value, "remote_port", ntohs(from_id));
		}
		add_assoc_string(return_value, "remote_ip", inet_ntoa(sin_addr), 1);
		return;
	}

	//connection is closed
	if (conn->active == 0)
	{
		RETURN_FALSE;
	}
	else
	{
		array_init(return_value);
		add_assoc_long(return_value, "from_id", conn->from_id);
		add_assoc_long(return_value, "from_fd", conn->from_fd);
		add_assoc_long(return_value, "connect_time", conn->connect_time);
		add_assoc_long(return_value, "last_time", conn->last_time);
		add_assoc_long(return_value, "from_port",  serv->connection_list[conn->from_fd].addr.sin_port);
		add_assoc_long(return_value, "remote_port", ntohs(conn->addr.sin_port));
		add_assoc_string(return_value, "remote_ip", inet_ntoa(conn->addr.sin_addr), 1);
	}
}

PHP_FUNCTION(swoole_connection_list)
{
	zval *zobject = getThis();
	swServer *serv;
	long start_fd = 0;
	long find_count = 10;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ll", &zobject, swoole_server_class_entry_ptr, &start_fd, &find_count) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &start_fd, &find_count) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	//超过最大查找数量
	if (find_count > SW_MAX_FIND_COUNT)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_connection_list max_find_count=%d", SW_MAX_FIND_COUNT);
		RETURN_FALSE;
	}

	//复制出来避免被其他进程改写
	int serv_max_fd = swServer_get_maxfd(serv);

	if (start_fd == 0)
	{
		start_fd = swServer_get_minfd(serv);
	}

	//达到最大，表示已经取完了
	if ((int)start_fd >= serv_max_fd)
	{
		RETURN_FALSE;
	}
	array_init(return_value);
	int fd = start_fd+1;

	//循环到最大fd
	for(; fd<= serv_max_fd; fd++)
	{
		 swTrace("maxfd=%d|fd=%d|find_count=%ld|start_fd=%ld", serv_max_fd, fd, find_count, start_fd);
		 if (serv->connection_list[fd].active == 1)
		 {
			 add_next_index_long(return_value, fd);
			 find_count--;
		 }
		 //finish fetch
		 if (find_count <= 0)
		 {
			 break;
		 }
	}
	//sw_log(SW_END_LINE);
}

static int php_swoole_onReceive(swFactory *factory, swEventData *req)
{
	swServer *serv = factory->ptr;
	zval *zserv = (zval *)serv->ptr2;
	zval **args[4];

	zval *zfd;
	zval *zfrom_id;
	zval *zdata;
	zval *retval;

	//UDP使用from_id作为port,fd做为ip
	php_swoole_udp_t udp_info;

	MAKE_STD_ZVAL(zfd);
	MAKE_STD_ZVAL(zfrom_id);
	MAKE_STD_ZVAL(zdata);

	//udp
	if (req->info.type == SW_EVENT_UDP)
	{
		udp_info.from_fd = req->info.from_fd;
		udp_info.port = req->info.from_id;
		memcpy(&php_swoole_udp_from_id, &udp_info, sizeof(php_swoole_udp_from_id));
		factory->last_from_id = php_swoole_udp_from_id;
		swTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t)req->info.from_id, req->info.from_fd);

		ZVAL_LONG(zfrom_id, (long) php_swoole_udp_from_id);
		ZVAL_LONG(zfd, (long)req->info.fd);
	}
	//unix dgram
	else if (req->info.type == SW_EVENT_UNIX_DGRAM)
	{
		uint16_t sun_path_offset = req->info.fd;
		ZVAL_STRING(zfd, req->data + sun_path_offset, 1);
		req->info.len -= (Z_STRLEN_P(zfd) + 1);
		ZVAL_LONG(zfrom_id, (long)req->info.from_fd);
		php_swoole_unix_dgram_fd = req->info.from_fd;
	}
	else
	{
		ZVAL_LONG(zfrom_id, (long)req->info.from_id);
		ZVAL_LONG(zfd, (long)req->info.fd);
	}

	char *data_ptr;
	int data_len;

#ifdef SW_USE_RINGBUFFER
	if (req->info.type == SW_EVENT_PACKAGE)
	{
		swPackage package;
		memcpy(&package, req->data, sizeof(package));

		data_ptr = package.data;
		data_len = package.length;

		//swoole_dump_bin(package.data, 's', package.length);
	}
#else
	if (req->info.type == SW_EVENT_PACKAGE_END)
	{
		data_ptr = SwooleWG.buffer_input[req->info.from_id]->str;
		data_len = SwooleWG.buffer_input[req->info.from_id]->length;
	}
#endif
	else
	{
		data_ptr = req->data;
		data_len = req->info.len;
	}

	//zero copy
	//ZVAL_STRINGL(zdata, data_ptr, data_len, 0);
	ZVAL_STRINGL(zdata, data_ptr, data_len, 1);

#ifdef SW_USE_RINGBUFFER
	if (req->info.type == SW_EVENT_PACKAGE)
	{
	    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);
	    worker->pool_input->free(worker->pool_input, data_ptr);
	}
#endif

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;
	args[3] = &zdata;

	//printf("req: fd=%d|len=%d|from_id=%d|data=%s\n", req->fd, req->len, req->from_id, req->data);

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onReceive], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onReceive handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	//zero copy
	//efree(zdata);
	zval_ptr_dtor(&zdata);

	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

static int php_swoole_onTask(swServer *serv, swEventData *req)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[4];

	zval *zfd;
	zval *zfrom_id;
	zval *zdata;
	zval *retval;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	//for swoole_server_finish
	sw_current_task = req;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, (long)req->info.fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, (long)req->info.from_id);

	MAKE_STD_ZVAL(zdata);

	if (swTaskWorker_is_large(req))
	{
		int data_len;
		void *buf;
		swTaskWorker_large_unpack(req, emalloc, buf, data_len);

		/**
		 * unpack failed
		 */
		if (data_len == -1)
		{
			efree(buf);
			return SW_OK;
		}
		ZVAL_STRINGL(zdata, buf, data_len, 0);
	}
	else
	{
		ZVAL_STRINGL(zdata, req->data, req->info.len, 1);
	}

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;
	args[3] = &zdata;

	//printf("task: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTask], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTask handler error");
	}

	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	zval_ptr_dtor(&zdata);

	if (retval != NULL)
	{
		if (Z_TYPE_P(retval) == IS_STRING)
		{
			php_swoole_task_finish(serv, Z_STRVAL_P(retval), Z_STRLEN_P(retval) TSRMLS_CC);
		}
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

static int php_swoole_onFinish(swServer *serv, swEventData *req)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[3];

	zval *ztask_id;
	zval *zdata;
	zval *retval;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	MAKE_STD_ZVAL(ztask_id);
	ZVAL_LONG(ztask_id, (long)req->info.fd);

	MAKE_STD_ZVAL(zdata);
	if (swTaskWorker_is_large(req))
	{
		int data_len;
		void *buf;
		swTaskWorker_large_unpack(req, emalloc, buf, data_len);

		/**
		 * unpack failed
		 */
		if (data_len == -1)
		{
			efree(buf);
			return SW_OK;
		}
		ZVAL_STRINGL(zdata, buf, data_len, 0);
	}
	else
	{
		ZVAL_STRINGL(zdata, req->data, req->info.len, 1);
	}

	args[0] = &zserv;
	args[1] = &ztask_id;
	args[2] = &zdata;

	//swTraceLog(60, "req: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onFinish], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onFinish handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	zval_ptr_dtor(&ztask_id);
	zval_ptr_dtor(&zdata);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

static void php_swoole_onStart(swServer *serv)
{
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	zval *zmaster_pid, *zmanager_pid;

	MAKE_STD_ZVAL(zmaster_pid);
	ZVAL_LONG(zmaster_pid, SwooleGS->master_pid);

	MAKE_STD_ZVAL(zmanager_pid);
	ZVAL_LONG(zmanager_pid, (serv->factory_mode == SW_MODE_PROCESS)?SwooleGS->manager_pid:0);

	zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), zmaster_pid TSRMLS_CC);
	zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), zmanager_pid TSRMLS_CC);

	zval_ptr_dtor(&zmaster_pid);
	zval_ptr_dtor(&zmanager_pid);

	args[0] = &zserv;
	zval_add_ref(&zserv);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onStart handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onManagerStart(swServer *serv)
{
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;
	zval_add_ref(&zserv);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStart handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onManagerStop(swServer *serv)
{
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;
	zval_add_ref(&zserv);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onManagerStop], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onManagerStop handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onTimer(swServer *serv, int interval)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[2];
	zval *retval;
	zval *zinterval;

	MAKE_STD_ZVAL(zinterval);
	ZVAL_LONG(zinterval, interval);

	args[0] = &zserv;
	args[1] = &zinterval;
	zval_add_ref(&zserv);
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTimer], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onTimer handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	zval_ptr_dtor(&zinterval);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onShutdown(swServer *serv)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;
	zval_add_ref(&zserv);
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onShutdown], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onShutdown handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onWorkerStart(swServer *serv, int worker_id)
{
	zval *zserv = (zval *)serv->ptr2;
	zval *zworker_id;
	zval **args[2]; //这里必须与下面的数字对应
	zval *retval;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	MAKE_STD_ZVAL(zworker_id);
	ZVAL_LONG(zworker_id, worker_id);

	args[0] = &zserv;
	zval_add_ref(&zserv);
	args[1] = &zworker_id;

	/**
	 * Manager Process ID
	 */
	zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), SwooleGS->manager_pid TSRMLS_CC);

	/**
	 * Worker ID
	 */
	zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_id"), zworker_id TSRMLS_CC);

	/**
	 * Worker Process ID
	 */
	zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_pid"), getpid() TSRMLS_CC);

	/**
	 * Have not set the event callback
	 */
	if (php_sw_callback[SW_SERVER_CB_onWorkerStart] == NULL)
	{
		return;
	}

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStart], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStart handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zworker_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onWorkerStop(swServer *serv, int worker_id)
{
	zval *zobject = (zval *)serv->ptr2;
	zval *zworker_id;
	zval **args[2]; //这里必须与下面的数字对应
	zval *retval;

	MAKE_STD_ZVAL(zworker_id);
	ZVAL_LONG(zworker_id, worker_id);

	zval_add_ref(&zobject);
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	// 这里是什么逻辑？
//	if (php_sw_callback[SW_SERVER_CB_onWorkerStop] == NULL)
//	{
//		args[0] = &zworker_id;
//		zval func;
//		ZVAL_STRING(&func, "onWorkerStop", 0);
//
//		if (call_user_function_ex(EG(function_table), &zobject, &func, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
//		{
//			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStop handler error");
//		}
//	}

	args[0] = &zobject;
	args[1] = &zworker_id;
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStop], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerStop handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zworker_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}


static void php_swoole_onWorkerError(swServer *serv, int worker_id, pid_t worker_pid, int exit_code)
{
	zval *zobject = (zval *)serv->ptr2;
	zval *zworker_id, *zworker_pid, *zexit_code;
	zval **args[4];
	zval *retval;

	MAKE_STD_ZVAL(zworker_id);
	ZVAL_LONG(zworker_id, worker_id);

	MAKE_STD_ZVAL(zworker_pid);
	ZVAL_LONG(zworker_pid, worker_pid);

	MAKE_STD_ZVAL(zexit_code);
	ZVAL_LONG(zexit_code, exit_code);

	zval_add_ref(&zobject);
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	args[0] = &zobject;
	args[1] = &zworker_id;
	args[2] = &zworker_pid;
	args[3] = &zexit_code;

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerError], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onWorkerError handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zworker_id);
	zval_ptr_dtor(&zworker_pid);
	zval_ptr_dtor(&zexit_code);

	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onConnect(swServer *serv, int fd, int from_id)
{
	zval *zserv = (zval *) serv->ptr2;
	zval *zfd;
	zval *zfrom_id;
	zval **args[3];
	zval *retval;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, from_id);

	args[0] = &zserv;
	zval_add_ref(&zserv);
	args[1] = &zfd;
	args[2] = &zfrom_id;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onConnect], &retval, 3, args, 0,
			NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onConnect handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

static void php_swoole_onClose(swServer *serv, int fd, int from_id)
{
	zval *zserv = (zval *) serv->ptr2;
	zval *zfd;
	zval *zfrom_id;
	zval **args[3];
	zval *retval;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, from_id);

	args[0] = &zserv;
	zval_add_ref(&zserv);
	args[1] = &zfd;
	args[2] = &zfrom_id;

//	php_printf("fd=%d|from_id=%d\n", fd, from_id);

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onClose], &retval, 3, args, 0,
			NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: onClose handler error");
	}
	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
	}

	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

PHP_FUNCTION(swoole_strerror)
{
	int swoole_errno = 0;
	char error_msg[256] = {0};
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &swoole_errno) == FAILURE) {
		return ;
	}
	snprintf(error_msg, sizeof(error_msg) -1 , "%s", strerror(swoole_errno));
    RETURN_STRING(error_msg, 1);
}

PHP_FUNCTION(swoole_errno)
{
    RETURN_LONG(errno);
}

PHP_FUNCTION(swoole_server_start)
{
	zval *zobject = getThis();
	swServer *serv;
	int ret;

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server::start.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	/*
	 * optional callback
	 */
	if (php_sw_callback[SW_SERVER_CB_onStart] != NULL)
	{
		serv->onStart = php_swoole_onStart;
	}
	if (php_sw_callback[SW_SERVER_CB_onShutdown] != NULL)
	{
		serv->onShutdown = php_swoole_onShutdown;
	}
	/**
	 * require callback, set the master/manager/worker PID
	 */
	serv->onWorkerStart = php_swoole_onWorkerStart;

	if (php_sw_callback[SW_SERVER_CB_onWorkerStop] != NULL)
	{
		serv->onWorkerStop = php_swoole_onWorkerStop;
	}
	if (php_sw_callback[SW_SERVER_CB_onTask] != NULL)
	{
		serv->onTask = php_swoole_onTask;
	}
	if (php_sw_callback[SW_SERVER_CB_onFinish] != NULL)
	{
		serv->onFinish = php_swoole_onFinish;
	}
	if (php_sw_callback[SW_SERVER_CB_onWorkerError] != NULL)
	{
		serv->onWorkerError = php_swoole_onWorkerError;
	}
	if (php_sw_callback[SW_SERVER_CB_onManagerStart] != NULL)
	{
		serv->onManagerStart = php_swoole_onManagerStart;
	}
	if (php_sw_callback[SW_SERVER_CB_onManagerStop] != NULL)
	{
		serv->onManagerStop = php_swoole_onManagerStop;
	}
	//-------------------------------------------------------------
	if (php_sw_callback[SW_SERVER_CB_onTimer] != NULL)
	{
		serv->onTimer = php_swoole_onTimer;
	}
 	if (php_sw_callback[SW_SERVER_CB_onClose] != NULL)
 	{
 		serv->onClose = php_swoole_onClose;
 	}
 	if (php_sw_callback[SW_SERVER_CB_onConnect] != NULL)
 	{
 		serv->onConnect = php_swoole_onConnect;
 	}
	if (php_sw_callback[SW_SERVER_CB_onReceive] == NULL)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onReceive callback");
		RETURN_FALSE;
	}
	//-------------------------------------------------------------
	serv->onReceive = php_swoole_onReceive;

	zval_add_ref(&zobject);
	serv->ptr2 = zobject;

	ret = swServer_create(serv);

	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "create server failed. Error: %s", sw_error);
		RETURN_LONG(ret);
	}

	/**
     * Master Process ID
     */
    zend_update_property_long(swoole_server_class_entry_ptr, zobject, ZEND_STRL("master_pid"), getpid() TSRMLS_CC);

	ret = swServer_start(serv);
	if (ret < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "start server failed. Error: %s", sw_error);
		RETURN_LONG(ret);
	}
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_send)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	swFactory *factory = NULL;
	swSendData _send;

	char *send_data;
	int send_len;

	zval *zfd;

	long _fd = 0;
	long from_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ozs|l", &zobject, swoole_server_class_entry_ptr, &zfd, &send_data,
				&send_len, &from_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|l", &zfd, &send_data,
				&send_len, &from_id) == FAILURE)
		{
			return;
		}
	}

	if (send_len <= 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
		RETURN_FALSE;
	}

	SWOOLE_GET_SERVER(zobject, serv);
	factory = &(serv->factory);

	if (Z_TYPE_P(zfd) == IS_STRING)
	{
		//unix dgram
		if (!is_numeric_string(Z_STRVAL_P(zfd), Z_STRLEN_P(zfd), &_fd, NULL, 0))
		{
			_send.info.fd = (int)_fd;
			_send.info.type = SW_EVENT_UNIX_DGRAM;
			_send.info.from_fd = (from_id > 0) ? from_id : php_swoole_unix_dgram_fd;
			_send.sun_path = Z_STRVAL_P(zfd);
			_send.sun_path_len = Z_STRLEN_P(zfd);
			_send.info.len = send_len;
			_send.data = send_data;
			SW_CHECK_RETURN(factory->finish(factory, &_send));
		}
	}
	else
	{
		_fd = Z_LVAL_P(zfd);
	}

	uint32_t fd = (uint32_t) _fd;

	//UDP, UDP必然超过0x1000000
	//原因：IPv4的第4字节最小为1,而这里的conn_fd是网络字节序
	if (fd > 0x1000000)
	{
		if (from_id == -1)
		{
			from_id = php_swoole_udp_from_id;
		}
		php_swoole_udp_t udp_info;
		memcpy(&udp_info, &from_id, sizeof(udp_info));

		_send.info.fd = fd;
		_send.info.from_id = (uint16_t)(udp_info.port);
		_send.info.from_fd = (uint16_t)(udp_info.from_fd);
		_send.info.type = SW_EVENT_UDP;
		_send.data = send_data;
		_send.info.len = send_len;
		swTrace("udp send: fd=%d|from_id=%d|from_fd=%d", _send.info.fd, (uint16_t)_send.info.from_id, _send.info.from_fd);
		SW_CHECK_RETURN(factory->finish(factory, &_send));
	}
	//TCP
	else
	{
		SW_CHECK_RETURN(swServer_tcp_send(serv, fd, send_data, send_len));
	}
}

PHP_FUNCTION(swoole_server_sendfile)
{
	zval *zobject = getThis();
	swServer *serv;
	swSendData send_data;
	char buffer[SW_BUFFER_SIZE];
	char *filename;
	long conn_fd;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ols", &zobject, swoole_server_class_entry_ptr, &conn_fd, &filename, &send_data.info.len) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &conn_fd, &filename, &send_data.info.len) == FAILURE)
		{
			return;
		}
	}

	//check fd
	if (conn_fd <= 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid fd[%ld] error.", conn_fd);
		RETURN_FALSE;
	}

    //file name size
    if (send_data.info.len > SW_BUFFER_SIZE - 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "sendfile name too long. [MAX_LENGTH=%d]", (int) SW_BUFFER_SIZE - 1);
        RETURN_FALSE;
    }
    //check file exists
    if (access(filename, R_OK) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "file[%s] not found.", filename);
        RETURN_FALSE;
    }

    SWOOLE_GET_SERVER(zobject, serv);

    send_data.info.fd = (int) conn_fd;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, filename, send_data.info.len);
    buffer[send_data.info.len] = 0;
    send_data.info.len++;

    send_data.data = buffer;
    SW_CHECK_RETURN(serv->factory.finish(&serv->factory, &send_data));
}

PHP_FUNCTION(swoole_server_addlisten)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	char *host;
	int host_len;
	long sock_type;
	long port;

	if (SwooleGS->start > 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to add listener.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osll", &zobject, swoole_server_class_entry_ptr, &host, &host_len, &port, &sock_type) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll", &host, &host_len, &port, &sock_type) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	SW_CHECK_RETURN(swServer_addListener(serv, (int)sock_type, host, (int)port));
}

PHP_FUNCTION(swoole_server_deltimer)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	long interval;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol", &zobject, swoole_server_class_entry_ptr, &interval) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &interval) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	if (SwooleG.timer.fd == 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: no timer.");
		RETURN_FALSE;
	}
	swTimer_del(&SwooleG.timer, (int)interval);
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_gettimer)
{
    zval *zobject = getThis();
    swServer *serv = NULL;
    long interval;

    if (zobject == NULL)
    {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr, &interval) == FAILURE)
        {
            return;
        }
    }
    SWOOLE_GET_SERVER(zobject, serv);

    if (SwooleG.timer.list == NULL)
    {
        RETURN_FALSE;
    }

    swTimer_node *timer_node;
    uint64_t key;
    array_init(return_value);

    do
    {
        timer_node = swHashMap_each_int(SwooleG.timer.list, &key);
        if (timer_node == NULL)
        {
            break;
        }
        add_next_index_long(return_value, key);

    } while(timer_node);
}

PHP_FUNCTION(swoole_server_addtimer)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	long interval;

	if (swIsMaster())
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "master process can not use timer.");
	    RETURN_FALSE;
	}

	if (php_sw_callback[SW_SERVER_CB_onTimer] == NULL)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "onTimer is null, Can not use timer.");
		RETURN_FALSE;
	}

	SWOOLE_GET_SERVER(zobject, serv);

	if (SwooleG.use_timer_pipe && SwooleG.main_reactor == NULL)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "can not use addtimer here.");
		RETURN_FALSE;
	}

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol", &zobject, swoole_server_class_entry_ptr, &interval) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &interval) == FAILURE)
		{
			return;
		}
	}

	SW_CHECK_RETURN(swServer_addTimer(serv, (int)interval));
}

PHP_FUNCTION(swoole_set_process_name)
{
	char *name;
	int name_len;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len) == FAILURE)
	{
		return;
	}
	//it's safe.
#define ARGV_MAX_LENGTH 127
	bzero(sapi_module.executable_location, ARGV_MAX_LENGTH);
	memcpy(sapi_module.executable_location, name, name_len);
}

PHP_FUNCTION(swoole_get_local_ip)
{
	struct sockaddr_in *s4;
	struct ifaddrs *ipaddrs, *ifa;
	void *in_addr;
	char ip[64];

	if (getifaddrs(&ipaddrs) != 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "getifaddrs() failed. Error: %s[%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	array_init(return_value);
	for (ifa = ipaddrs; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP))
		{
			continue;
		}

		switch (ifa->ifa_addr->sa_family)
		{
			case AF_INET:
				s4 = (struct sockaddr_in *)ifa->ifa_addr;
				in_addr = &s4->sin_addr;
				break;
			case AF_INET6:
				//struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				//in_addr = &s6->sin6_addr;
				continue;
			default:
				continue;
		}
		if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, ip, sizeof(ip)))
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s: inet_ntop failed.", ifa->ifa_name);
		}
		else
		{
			//if (ifa->ifa_addr->sa_family == AF_INET && ntohl(((struct in_addr *) in_addr)->s_addr) == INADDR_LOOPBACK)
			if (strcmp(ip, "127.0.0.1") == 0)
			{
				continue;
			}
			add_assoc_string(return_value, ifa->ifa_name, ip, 1);
		}
	}
	freeifaddrs(ipaddrs);
}

static int php_swoole_task_finish(swServer *serv, char *data, int data_len TSRMLS_DC)
{
	swEventData buf;
	if (SwooleG.task_worker_num < 1)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: finish can not use here");
		return SW_ERR;
	}

	int ret;

	//for swoole_server_task
	if (sw_current_task->info.type == SW_TASK_NONBLOCK)
	{
		buf.info.type = SW_EVENT_FINISH;
		buf.info.fd = sw_current_task->info.fd;

		//write to file
		if (data_len >= sizeof(buf.data))
		{
			if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
				return SW_ERR;
			}
		}
		else
		{
			memcpy(buf.data, data, data_len);
			buf.info.len = data_len;
			buf.info.from_fd = 0;
		}

		if (serv->factory_mode == SW_MODE_PROCESS)
		{
            ret = swFactoryProcess_send2worker(serv, &buf, sizeof(buf) + buf.info.len, sw_current_task->info.from_id);
		}
		else
		{
			ret = write(SwooleG.event_workers->workers[sw_current_task->info.from_id].pipe_worker, &buf, sizeof(buf.info)+data_len);
		}
	}
	else
	{
		uint64_t flag = 1;
		uint16_t worker_id = sw_current_task->info.from_id;

		/**
		 * Use worker shm store the result
		 */
		swEventData *result = &(SwooleG.task_result[worker_id]);
		swPipe *task_notify_pipe = &(SwooleG.task_notify[worker_id]);

		result->info.type = SW_EVENT_FINISH;
		result->info.fd = sw_current_task->info.fd;

		if (data_len >= sizeof(buf.data))
		{
			if (swTaskWorker_large_pack(result, data, data_len) < 0 )
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
				return SW_ERR;
			}
		}
		else
		{
			memcpy(result->data, data, data_len);
			result->info.len = data_len;
			result->info.from_fd = 0;
		}

		while(1)
		{
			ret = task_notify_pipe->write(task_notify_pipe, &flag, sizeof(flag));
			if (errno == EINTR)
			{
				continue;
			}
			else if (errno == EAGAIN)
			{
				swYield();
				continue;
			}
			else
			{
				break;
			}
		}
	}
	if (ret < 0)
	{
		swWarn("TaskWorker: send result to worker failed. Error: %s[%d]", strerror(errno), errno);
	}
	return ret;
}

PHP_FUNCTION(swoole_server_taskwait)
{
	zval *zobject = getThis();
	swEventData buf;
	swServer *serv;

	double timeout = SW_TASKWAIT_TIMEOUT;
	char *data;
	int data_len;
	long worker_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os|dl", &zobject, swoole_server_class_entry_ptr, &data, &data_len, &timeout, &worker_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|dl", &data, &data_len, &timeout, &worker_id) == FAILURE)
		{
			return;
		}
	}

	SWOOLE_GET_SERVER(zobject, serv);

	if (SwooleG.task_worker_num < 1)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: task can not use. Please set task_worker_num.");
		RETURN_FALSE;
	}

	if (worker_id >= SwooleG.task_worker_num)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_server: worker_id must be less than serv->task_worker_num");
		RETURN_FALSE;
	}

	buf.info.type = SW_TASK_BLOCKING;
	//field fd save task_id
	buf.info.fd = php_swoole_task_id++;
	//field from_id save the worker_id
	buf.info.from_id = SwooleWG.id;
	//clear result buffer
	swEventData *task_result = &(SwooleG.task_result[SwooleWG.id]);
	bzero(task_result, sizeof(SwooleG.task_result[SwooleWG.id]));

	int64_t notify;

	if (data_len >= sizeof(buf.data))
	{
		if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
			RETURN_FALSE;
		}
	}
	else
	{
		memcpy(buf.data, data, data_len);
		buf.info.len = data_len;
		buf.info.from_fd = 0;
	}

	if (swProcessPool_dispatch(&SwooleG.task_workers, &buf, (int) worker_id) >= 0)
	{
		/**
		 * setTimeout
		 */
		swPipe *task_notify_pipe = &SwooleG.task_notify[SwooleWG.id];
		task_notify_pipe->timeout = timeout;

		if (task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify)) > 0)
		{
			/**
			 * Large result package
			 */
			if (swTaskWorker_is_large(task_result))
			{
				int data_len;
				void *buf;
				swTaskWorker_large_unpack(task_result, emalloc, buf, data_len);
				/**
				 * unpack failed
				 */
				if (data_len == -1)
				{
					efree(buf);
					RETURN_FALSE;
				}
				RETURN_STRINGL(buf, data_len, 0);
			}
			else
			{
				RETURN_STRINGL(task_result->data, task_result->info.len, 1);
			}
		}
		else
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "taskwait failed. Error: %s[%d]", strerror(errno), errno);
		}
	}
	RETURN_FALSE;
}

PHP_FUNCTION(swoole_server_task)
{
	zval *zobject = getThis();
	swEventData buf;
	swServer *serv;
	char *data;
	int data_len;
	long worker_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os|l", &zobject, swoole_server_class_entry_ptr, &data, &data_len, &worker_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &data, &data_len, &worker_id) == FAILURE)
		{
			return;
		}
	}

	SWOOLE_GET_SERVER(zobject, serv);
	if (SwooleG.task_worker_num < 1)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "task can not use. Please set task_worker_num.");
		RETURN_FALSE;
	}

	if (worker_id >= SwooleG.task_worker_num)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "worker_id must be less than serv->task_worker_num");
		RETURN_FALSE;
	}

	buf.info.type = SW_TASK_NONBLOCK;
	//使用fd保存task_id
	buf.info.fd = php_swoole_task_id++;
	//from_id保存worker_id
	buf.info.from_id = SwooleWG.id;

	//write to file
	if (data_len >= sizeof(buf.data))
	{
		if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "large task pack failed()");
			RETURN_FALSE;
		}
	}
	else
	{
		memcpy(buf.data, data, data_len);
		buf.info.len = data_len;
		buf.info.from_fd = 0;
	}

	if (swProcessPool_dispatch(&SwooleG.task_workers, &buf, (int) worker_id) >= 0)
	{
		RETURN_LONG(buf.info.fd);
	}
	else
	{
		RETURN_FALSE;
	}
}

PHP_FUNCTION(swoole_server_finish)
{
	zval *zobject = getThis();
	swServer *serv = NULL;

	char *data;
	int data_len;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os", &zobject, swoole_server_class_entry_ptr, &data, &data_len) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	SW_CHECK_RETURN(php_swoole_task_finish(serv, data, data_len TSRMLS_CC));
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
