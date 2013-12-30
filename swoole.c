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
#include <ext/standard/info.h>

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define SW_HOST_SIZE            128

#pragma pack(4)
typedef struct {
	uint16_t port;
	uint16_t from_fd;
} php_swoole_udp_t;
#pragma pack()

zval *php_sw_callback[PHP_SERVER_CALLBACK_NUM];

HashTable php_sw_reactor_callback;
HashTable php_sw_client_callback;

#ifdef ZTS
void ***sw_thread_ctx;
#endif

static swEventData *sw_current_task;
static int php_swoole_task_id;
static int php_swoole_udp_from_fd;

extern sapi_module_struct sapi_module;

static int php_swoole_onReceive(swFactory *, swEventData *);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onConnect(swServer *, int fd, int from_id);
static void php_swoole_onClose(swServer *, int fd, int from_id);
static void php_swoole_onTimer(swServer *serv, int interval);
static void php_swoole_onWorkerStart(swServer *, int worker_id);
static void php_swoole_onWorkerStop(swServer *, int worker_id);
static void php_swoole_onMasterConnect(swServer *, int fd, int from_id);
static void php_swoole_onMasterClose(swServer *, int fd, int from_id);
static int php_swoole_onTask(swServer *, swEventData *task);
static int php_swoole_onFinish(swServer *, swEventData *task);

static void swoole_destory_server(zend_rsrc_list_entry *rsrc TSRMLS_DC);
static void swoole_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC);

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

const zend_function_entry swoole_functions[] =
{
	PHP_FE(swoole_version, NULL)
	PHP_FE(swoole_server_create, NULL)
	PHP_FE(swoole_server_set, NULL)
	PHP_FE(swoole_server_start, NULL)
	PHP_FE(swoole_server_send, NULL)
	PHP_FE(swoole_server_close, NULL)
	PHP_FE(swoole_server_handler, NULL)
	PHP_FE(swoole_server_on, NULL)
	PHP_FE(swoole_server_addlisten, NULL)
	PHP_FE(swoole_server_addtimer, NULL)
	PHP_FE(swoole_server_deltimer, NULL)
	PHP_FE(swoole_server_task, NULL)
	PHP_FE(swoole_server_taskwait, NULL)
	PHP_FE(swoole_server_finish, NULL)
	PHP_FE(swoole_server_reload, NULL)
	PHP_FE(swoole_server_shutdown, NULL)
	PHP_FE(swoole_connection_info, NULL)
	PHP_FE(swoole_connection_list, NULL)
	PHP_FE(swoole_event_add, NULL)
	PHP_FE(swoole_event_del, NULL)
	PHP_FE(swoole_event_exit, NULL)
	PHP_FE(swoole_event_wait, NULL)
	PHP_FE(swoole_client_select, NULL)
	PHP_FE(swoole_set_process_name, NULL)
#ifdef SW_ASYNC_MYSQL
	PHP_FE(swoole_get_mysqli_sock, NULL)
#endif
	PHP_FE_END /* Must be the last line in swoole_functions[] */
};

static zend_function_entry swoole_server_methods[] = {
	PHP_FALIAS(__construct, swoole_server_create, NULL)
	PHP_FALIAS(set, swoole_server_set, NULL)
	PHP_FALIAS(start, swoole_server_start, NULL)
	PHP_FALIAS(send, swoole_server_send, NULL)
	PHP_FALIAS(close, swoole_server_close, NULL)
	PHP_FALIAS(task, swoole_server_task, NULL)
	PHP_FALIAS(taskwait, swoole_server_taskwait, NULL)
	PHP_FALIAS(finish, swoole_server_finish, NULL)
	PHP_FALIAS(addlistener, swoole_server_addlisten, NULL)
	PHP_FALIAS(addtimer, swoole_server_addtimer, NULL)
	PHP_FALIAS(deltimer, swoole_server_deltimer, NULL)
	PHP_FALIAS(reload, swoole_server_reload, NULL)
	PHP_FALIAS(shutdown, swoole_server_shutdown, NULL)
	PHP_FALIAS(handler, swoole_server_handler, NULL)
	PHP_FALIAS(on, swoole_server_on, NULL)
	PHP_FALIAS(connection_info, swoole_connection_info, NULL)
	PHP_FALIAS(connection_list, swoole_connection_list, NULL)
	{NULL, NULL, NULL}
};

const zend_function_entry swoole_client_methods[] =
{
	PHP_ME(swoole_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(swoole_client, connect, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, recv, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, send, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, close, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, on, NULL, ZEND_ACC_PUBLIC)
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

zend_class_entry swoole_lock_ce;
zend_class_entry *swoole_lock_class_entry_ptr;

zend_class_entry swoole_client_ce;
zend_class_entry *swoole_client_class_entry_ptr;

zend_class_entry swoole_server_ce;
zend_class_entry *swoole_server_class_entry_ptr;

zend_module_entry swoole_module_entry =
{
#if ZEND_MODULE_API_NO >= 20050922
	STANDARD_MODULE_HEADER_EX, NULL,
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
/* Remove comments and fill if you need to have entries in php.ini
 PHP_INI_BEGIN()
 STD_PHP_INI_ENTRY("swoole.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_swoole_globals, swoole_globals)
 STD_PHP_INI_ENTRY("swoole.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_swoole_globals, swoole_globals)
 PHP_INI_END()
 */
/* }}} */

/* {{{ php_swoole_init_globals
 */
/* Uncomment this function if you have INI entries
 static void php_swoole_init_globals(zend_swoole_globals *swoole_globals)
 {
 swoole_globals->global_value = 0;
 swoole_globals->global_string = NULL;
 }
 */
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(swoole)
{
	le_swoole_server = zend_register_list_destructors_ex(swoole_destory_server, NULL, SW_RES_SERVER_NAME, module_number);
	le_swoole_client = zend_register_list_destructors_ex(swoole_destory_client, NULL, SW_RES_CLIENT_NAME, module_number);
	le_swoole_lock = zend_register_list_destructors_ex(swoole_destory_lock, NULL, SW_RES_LOCK_NAME, module_number);

	REGISTER_LONG_CONSTANT("SWOOLE_BASE", SW_MODE_SINGLE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_THREAD", SW_MODE_THREAD, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", SW_MODE_PROCESS, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_RWLOCK", SW_RWLOCK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_FILELOCK", SW_FILELOCK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_MUTEX", SW_MUTEX, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SEM", SW_SEM, CONST_CS | CONST_PERSISTENT);
#ifdef HAVE_SPINLOCK
	REGISTER_LONG_CONSTANT("SWOOLE_SPINLOCK", SW_SPINLOCK, CONST_CS | CONST_PERSISTENT);
#endif

	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_SYNC", SW_SOCK_SYNC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_ASYNC", SW_SOCK_ASYNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRINGL_CONSTANT("SWOOLE_VERSION", PHP_SWOOLE_VERSION, sizeof(PHP_SWOOLE_VERSION) - 1, CONST_PERSISTENT | CONST_CS);

	INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", swoole_client_methods);
	swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);

	zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_server_ce, "swoole_server", swoole_server_methods);
	swoole_server_class_entry_ptr = zend_register_internal_class(&swoole_server_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_lock_ce, "swoole_lock", swoole_lock_methods);
	swoole_lock_class_entry_ptr = zend_register_internal_class(&swoole_lock_ce TSRMLS_CC);

	//swoole init
	swoole_init();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(swoole)
{
	swoole_clean();
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
	php_info_print_table_row(2, "epoll", "enable");
#endif
#ifdef HAVE_EVENTFD
    php_info_print_table_row(2, "event_fd", "enable");
#endif
#ifdef HAVE_KQUEUE
    php_info_print_table_row(2, "kqueue", "enable");
#endif
#ifdef HAVE_TIMERFD
    php_info_print_table_row(2, "timerfd", "enable");
#endif
#ifdef SW_USE_ACCEPT4
    php_info_print_table_row(2, "accept4", "enable");
#endif
#ifdef HAVE_CPU_AFFINITY
    php_info_print_table_row(2, "cpu affinity", "enable");
#endif
#ifdef HAVE_SPINLOCK
    php_info_print_table_row(2, "spinlock", "enable");
#endif
	php_info_print_table_end();
}
/* }}} */

PHP_RINIT_FUNCTION(swoole)
{
	//swoole_event_add
	zend_hash_init(&php_sw_reactor_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//swoole_client::on
	zend_hash_init(&php_sw_client_callback, 16, NULL, ZVAL_PTR_DTOR, 0);
	//running
	SwooleG.running = 1;
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(swoole)
{
	zend_hash_destroy(&php_sw_reactor_callback);
	zend_hash_destroy(&php_sw_client_callback);
	int i;
	for(i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(php_sw_callback[i] != NULL)
		{
			zval_dtor(php_sw_callback[i]);
		}
	}
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
	if(cli->sock != 0)
	{
		cli->close(cli);
	}
	efree(cli);
}

PHP_FUNCTION(swoole_version)
{
	char swoole_version[32] = {0};
	snprintf(swoole_version, sizeof(PHP_SWOOLE_VERSION), "%s", PHP_SWOOLE_VERSION);
    RETURN_STRING(swoole_version, 1);
}

#ifdef SW_ASYNC_MYSQL
PHP_FUNCTION(swoole_get_mysqli_sock)
{
	MY_MYSQL *mysql;
	zval *mysql_link;
	int sock;
	extern zend_class_entry *mysqli_link_class_entry;
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
	int host_len;
	char *serv_host;
	long sock_type = SW_SOCK_TCP;
	long serv_port;
	long serv_mode = SW_MODE_PROCESS;

	//only cli env
	if(strcasecmp("cli", sapi_module.name) != 0)
	{
		zend_error(E_ERROR, "SwooleServer must run at php_cli environment.");
		RETURN_FALSE;
	}
	swServer *serv = sw_malloc(sizeof(swServer));
	swServer_init(serv);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|ll", &serv_host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
	{
		return;
	}

	if(serv_mode == SW_MODE_THREAD)
	{
		serv_mode = SW_MODE_SINGLE;
		swWarn("PHP can not running at multi-threading. Reset mode to SW_MODE_BASE");
	}

	serv->factory_mode = serv_mode;
	swTrace("Create host=%s,port=%ld,mode=%d\n", serv_host, serv_port, serv->factory_mode);

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	bzero(php_sw_callback, sizeof(zval*)*PHP_SERVER_CALLBACK_NUM);

	if(swServer_addListen(serv, sock_type, serv_host, serv_port) < 0)
	{
		zend_error(E_ERROR, "swServer_addListen fail. Error: %s [%d]", strerror(errno), errno);
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
}

PHP_FUNCTION(swoole_server_set)
{
	zval *zset = NULL;
	zval *zobject = getThis();
	HashTable * vht;
	swServer *serv;
	zval **v;
	double timeout;

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
	//daemonize，守护进程化
	if (zend_hash_find(vht, ZEND_STRS("daemonize"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->daemonize = (int)Z_LVAL_PP(v);
	}
	//backlog
	if (zend_hash_find(vht, ZEND_STRS("backlog"), (void **)&v) == SUCCESS)
	{
		serv->backlog = (int)Z_LVAL_PP(v);
	}
	//poll_thread_num
	if (zend_hash_find(vht, ZEND_STRS("poll_thread_num"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->reactor_num = (int)Z_LVAL_PP(v);
	}
	if (zend_hash_find(vht, ZEND_STRS("reactor_num"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->reactor_num = (int)Z_LVAL_PP(v);
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
		serv->task_worker_num = (int)Z_LVAL_PP(v);
	}
	//max_conn
	if (zend_hash_find(vht, ZEND_STRS("max_conn"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->max_conn = (int)Z_LVAL_PP(v);
	}
	//max_request
	if (zend_hash_find(vht, ZEND_STRS("max_request"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->max_request = (int)Z_LVAL_PP(v);
	}
	//cpu affinity
	if (zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_cpu_affinity = (uint8_t)Z_LVAL_PP(v);
	}
	//tcp_nodelay
	if (zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_tcp_nodelay = (uint8_t)Z_LVAL_PP(v);
	}
	//tcp_keepalive
	if (zend_hash_find(vht, ZEND_STRS("open_tcp_keepalive"), (void **)&v) == SUCCESS)
	{
		serv->open_tcp_keepalive = (uint8_t)Z_LVAL_PP(v);
	}
	//data buffer, EOF检测
	if (zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->open_eof_check = (uint8_t)Z_LVAL_PP(v);
	}
	//data eof设置
	if (zend_hash_find(vht, ZEND_STRS("data_eof"), (void **) &v) == SUCCESS)
	{
		if (Z_STRLEN_PP(v) > SW_DATA_EOF_MAXLEN)
		{
			zend_error(E_ERROR, "swoole_server date_eof max length is %d", SW_DATA_EOF_MAXLEN);
			RETURN_FALSE;
		}
		memcpy(serv->data_eof, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
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
	//max_request
	if (zend_hash_find(vht, ZEND_STRS("dispatch_mode"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->dispatch_mode = (int)Z_LVAL_PP(v);
	}
	//log_file
	if (zend_hash_find(vht, ZEND_STRS("log_file"), (void **)&v) == SUCCESS)
	{
		memcpy(serv->log_file, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
	}
	//timer interval
	if (zend_hash_find(vht, ZEND_STRS("timer_interval"), (void **)&v) == SUCCESS)
	{
		convert_to_long(*v);
		serv->timer_interval = (int)Z_LVAL_PP(v);
	}
	RETURN_TRUE;
}

static int php_swoole_set_callback(int key, zval *cb TSRMLS_DC)
{
	char *func_name = NULL;
	if(!zend_is_callable(cb, 0, &func_name TSRMLS_CC))
	{
		zend_error(E_ERROR, "Function '%s' is not callable", func_name);
		efree(func_name);
		return SW_ERR;
	}
	//zval_add_ref(&cb);
	php_sw_callback[key] = pemalloc(sizeof(zval), 1);
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
	};
	for(i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(strncasecmp(callback[i], ha_name, len) == 0)
		{
			ret = php_swoole_set_callback(i, cb TSRMLS_CC);
			break;
		}
	}
	if(ret < 0)
	{
		zend_error(E_ERROR, "swoole_server_handler: unkown handler[%s].", ha_name);
	}
	ZVAL_BOOL(return_value, ret);
}


PHP_FUNCTION(swoole_server_on)
{
	zval *zobject = getThis();
	char *ha_name = NULL;
	int len, i;
	int ret = -1;
	swServer *serv;
	zval *cb;

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
	};
	for(i=0; i<PHP_SERVER_CALLBACK_NUM; i++)
	{
		if(strncasecmp(callback[i], ha_name, len) == 0)
		{
			ret = php_swoole_set_callback(i, cb TSRMLS_CC);
			break;
		}
	}
	if(ret < 0)
	{
		zend_error(E_ERROR, "swoole_server_on: unkown handler[%s].", ha_name);
	}
	ZVAL_BOOL(return_value, ret);
}


PHP_FUNCTION(swoole_server_close)
{
	zval *zobject = getThis();;
	swServer *serv;
	swEvent ev;
	long conn_fd, from_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ol|l", &zobject, swoole_server_class_entry_ptr, &conn_fd, &from_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &conn_fd, &from_id) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	if(from_id < 0)
	{
		ev.from_id = serv->factory.last_from_id;
	}
	else
	{
		ev.from_id = from_id;
	}
	ev.fd = (int)conn_fd;
	//主进程不应当执行此操作
	if(swIsMaster())
	{
		RETURN_FALSE;
	}
	SW_CHECK_RETURN(serv->factory.end(&serv->factory, &ev));
}

PHP_FUNCTION(swoole_server_reload)
{
	zval *zobject = getThis();;
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

PHP_FUNCTION(swoole_server_shutdown)
{
	zval *zobject = getThis();;
	swServer *serv;
	zval *zmaster_pid;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);
	zmaster_pid = zend_read_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("master_pid"), 0 TSRMLS_CC);
	if (zmaster_pid != NULL)
	{
		SW_CHECK_RETURN(kill(Z_LVAL_P(zmaster_pid), SIGTERM));
	}
	else
	{
		RETURN_FALSE;
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

	swConnection *conn = swServer_get_connection(serv, fd);
	//It's udp
	if(conn == NULL || from_id != -1)
	{
		array_init(return_value);
		swConnection *from_sock = swServer_get_connection(serv, from_id);
		struct in_addr sin_addr;
		sin_addr.s_addr = fd;
		if (from_sock != NULL)
		{
			add_assoc_long(return_value, "from_fd", from_id);
			add_assoc_long(return_value, "from_port",  serv->connection_list[from_id].addr.sin_port);
		}
		if (from_id !=0 )
		{
			add_assoc_long(return_value, "remote_port", ntohs(from_id));
		}
		add_assoc_string(return_value, "remote_ip", inet_ntoa(sin_addr), 1);
		return;
	}
	if(conn->tag == 0)
	{
		RETURN_FALSE;
	}
	else
	{
		array_init(return_value);
		add_assoc_long(return_value, "from_id", conn->from_id);
		add_assoc_long(return_value, "from_fd", conn->from_fd);
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
		zend_error(E_WARNING, "swoole_connection_list max_find_count=%d", SW_MAX_FIND_COUNT);
		RETURN_FALSE;
	}

	//复制出来避免被其他进程改写
	int serv_max_fd = swServer_get_maxfd(serv);

	if(start_fd == 0)
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
		 swTrace("maxfd=%d|fd=%d|find_count=%d|start_fd=%d", serv_max_fd, fd, find_count, start_fd);
		 if(serv->connection_list[fd].tag == 1)
		 {
			 add_next_index_long(return_value, fd);
			 find_count--;
		 }
		 //finish fetch
		 if(find_count <= 0)
		 {
			 break;
		 }
	}
	//sw_log(SW_END_LINE);
}

int php_swoole_onReceive(swFactory *factory, swEventData *req)
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

	int from_id;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, (long)req->info.fd);

	MAKE_STD_ZVAL(zfrom_id);
	if(req->info.type == SW_EVENT_UDP)
	{
		php_swoole_udp_from_fd = udp_info.from_fd = req->info.from_fd;
		udp_info.port = req->info.from_id;
		memcpy(&from_id, &udp_info, sizeof(from_id));
		swTrace("SendTo: from_id=%d|from_fd=%d", req->info.from_fd, req->info.from_id);
		ZVAL_LONG(zfrom_id, (long) from_id);
	}
	else
	{
		php_swoole_udp_from_fd = 0;
		ZVAL_LONG(zfrom_id, (long)req->info.from_id);
	}

	MAKE_STD_ZVAL(zdata);
	ZVAL_STRINGL(zdata, req->data, req->info.len, 1);

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;
	args[3] = &zdata;

	//printf("req: fd=%d|len=%d|from_id=%d|data=%s\n", req->fd, req->len, req->from_id, req->data);

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onReceive], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		if (EG(exception))
		{
			zend_error(E_WARNING, "SwoolServer: onReceive handler error. Uncaught exception Exception. Must try catch.");
		}
		else
		{
			zend_error(E_WARNING, "SwoolServer: onReceive handler error");
		}
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
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

	//for swoole_server_finish
	sw_current_task = req;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, (long)req->info.fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, (long)req->info.from_id);

	MAKE_STD_ZVAL(zdata);
	ZVAL_STRINGL(zdata, req->data, req->info.len, 1);

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;
	args[3] = &zdata;

//	printf("task: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onTask], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwoolServer: onReceive handler error");
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	zval_ptr_dtor(&zdata);
	if (retval != NULL)
	{
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

	MAKE_STD_ZVAL(ztask_id);
	ZVAL_LONG(ztask_id, (long)req->info.fd);

	MAKE_STD_ZVAL(zdata);
	ZVAL_STRINGL(zdata, req->data, req->info.len, 1);

	args[0] = &zserv;
	args[1] = &ztask_id;
	args[2] = &zdata;

//	printf("req: fd=%d|len=%d|from_id=%d|data=%s\n", req->info.fd, req->info.len, req->info.from_id, req->data);

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onFinish], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwoolServer: onReceive handler error");
	}
	zval_ptr_dtor(&ztask_id);
	zval_ptr_dtor(&zdata);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

void php_swoole_onStart(swServer *serv)
{
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	zval *zmaster_pid, *zmanager_pid;

	MAKE_STD_ZVAL(zmaster_pid);
	ZVAL_LONG(zmaster_pid, getpid());

	MAKE_STD_ZVAL(zmanager_pid);
	ZVAL_LONG(zmanager_pid, (serv->factory_mode == SW_MODE_PROCESS)?swServer_get_manager_pid(serv):0);

	zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), zmaster_pid TSRMLS_CC);
	zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("manager_pid"), zmanager_pid TSRMLS_CC);

	args[0] = &zserv;
	zval_add_ref(&zserv);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onStart handler error");
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onTimer(swServer *serv, int interval)
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
		zend_error(E_WARNING, "SwooleServer: onTimer handler error");
	}
	zval_ptr_dtor(&zinterval);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onShutdown(swServer *serv)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;
	zval_add_ref(&zserv);
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onShutdown], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onShutdown handler error");
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

	MAKE_STD_ZVAL(zworker_id);
	ZVAL_LONG(zworker_id, worker_id);

	args[0] = &zserv;
	zval_add_ref(&zserv);
	args[1] = &zworker_id;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStart], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onShutdown handler error");
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

	if (php_sw_callback[SW_SERVER_CB_onWorkerStop] == NULL)
	{
		args[0] = &zworker_id;
		zval func;
		ZVAL_STRING(&func, "onWorkerStop", 0);

		if (call_user_function_ex(EG(function_table), &zobject, &func, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "SwooleServer->onShutdown handler error");
		}
	}
	else
	{
		args[0] = &zobject;
		args[1] = &zworker_id;
		if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onWorkerStop], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "SwooleServer: onShutdown handler error");
		}
	}

	zval_ptr_dtor(&zworker_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onConnect(swServer *serv, int fd, int from_id)
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
		zend_error(E_WARNING, "SwooleServer: onConnect handler error");
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onClose(swServer *serv, int fd, int from_id)
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
		zend_error(E_WARNING, "SwooleServer: onClose handler error");
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onMasterConnect(swServer *serv, int fd, int from_id)
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
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onMasterConnect], &retval, 3, args, 0,
			NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: ononMasterConnect handler error");
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

void php_swoole_onMasterClose(swServer *serv, int fd, int from_id)
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
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[SW_SERVER_CB_onMasterClose], &retval, 3, args, 0,
			NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onMasterClose handler error");
	}
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zfrom_id);
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
}

PHP_FUNCTION(swoole_server_start)
{
	zval *zobject = getThis();
	swServer *serv;
	int ret;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zobject, swoole_server_class_entry_ptr) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	//可选事件
	if (php_sw_callback[SW_SERVER_CB_onStart] != NULL)
	{
		serv->onStart = php_swoole_onStart;
	}
	if (php_sw_callback[SW_SERVER_CB_onShutdown] != NULL)
	{
		serv->onShutdown = php_swoole_onShutdown;
	}
	if (php_sw_callback[SW_SERVER_CB_onMasterConnect] != NULL)
	{
		serv->onMasterConnect = php_swoole_onMasterConnect;
	}
	if (php_sw_callback[SW_SERVER_CB_onMasterClose] != NULL)
	{
		serv->onMasterClose = php_swoole_onMasterClose;
	}
	if (php_sw_callback[SW_SERVER_CB_onWorkerStart] != NULL)
	{
		serv->onWorkerStart = php_swoole_onWorkerStart;
	}
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
		zend_error(E_ERROR, "SwooleServer: onReceive must set.");
		RETURN_FALSE;
	}
	serv->onReceive = php_swoole_onReceive;

	zval_add_ref(&zobject);
	serv->ptr2 = zobject;
	ret = swServer_create(serv);

	if (ret < 0)
	{
		zend_error(E_ERROR, "SwooleServer: create server fail. Error: %s [%d][sw_error=%s]", strerror(errno), errno, sw_error);
		RETURN_LONG(ret);
	}
	ret = swServer_start(serv);
	if (ret < 0)
	{
		zend_error(E_ERROR, "SwooleServer: start server fail. Error: %s [%d][sw_error=%s]", strerror(errno), errno, sw_error);
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
	char buffer[SW_BUFFER_SIZE];

	char *send_data;
	int send_len;

	long conn_fd;
	long from_id = -1;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Ols|l", &zobject, swoole_server_class_entry_ptr, &conn_fd, &send_data,
				&send_len, &from_id) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls|l", &conn_fd, &send_data,
				&send_len, &from_id) == FAILURE)
		{
			return;
		}
	}
	SWOOLE_GET_SERVER(zobject, serv);

	factory = &(serv->factory);

	_send.info.fd = (int)conn_fd;

	//TCP
	if(php_swoole_udp_from_fd == 0)
	{
		if (from_id == -1)
		{
			_send.info.from_id = factory->last_from_id;
		}
		_send.info.type = SW_EVENT_TCP;
		_send.info.from_id = from_id;
	}
	//UDP
	else
	{
		php_swoole_udp_t udp_info;
		memcpy(&udp_info, (uint32_t *)(&from_id), sizeof(udp_info));
		_send.info.from_id = (uint16_t)(udp_info.port);
		_send.info.from_fd = (uint16_t)(udp_info.from_fd);
		_send.info.type = SW_EVENT_UDP;
	}
	_send.data = buffer;

	int ret=-1, i;

	//分页发送，需要去掉头部所在的尺寸
	int pagesize = SW_BUFFER_SIZE - sizeof(_send.info);

	int trunk_num = (send_len/pagesize) + 1;
	int send_n = 0;
//	swWarn("SendTo: trunk_num=%d|send_len=%d", trunk_num, send_len);
	for(i=0; i<trunk_num; i++)
	{
		//最后一页
		if(i == (trunk_num-1))
		{
			send_n = send_len % pagesize;
			if(send_n == 0) break;
		}
		else
		{
			send_n = pagesize;
		}
		memcpy(buffer, send_data + pagesize*i, send_n);
		_send.info.len = send_n;
		ret = factory->finish(factory, &_send);
	}
	SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_server_addlisten)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	char *host;
	int host_len;
	long sock_type;
	long port;

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
	SW_CHECK_RETURN(swServer_addListen(serv, (int)sock_type, host, (int)port));
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
	if (serv->timer_interval == 0 || SwooleG.timer.fd == 0)
	{
		zend_error(E_WARNING, "SwooleServer: no timer.");
		RETURN_FALSE;
	}
	swTimer_del(&SwooleG.timer, (int)interval);
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_addtimer)
{
	zval *zobject = getThis();
	swServer *serv = NULL;
	long interval;

	if (php_sw_callback[SW_SERVER_CB_onTimer] == NULL)
	{
		zend_error(E_WARNING, "SwooleServer: onTimer is null, Can not use timer.");
		RETURN_FALSE;
	}
	if (SwooleG.main_reactor == NULL)
	{
		zend_error(E_WARNING, "SwooleServer: can not use addtimer here.");
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
	SWOOLE_GET_SERVER(zobject, serv);
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

PHP_FUNCTION(swoole_server_taskwait)
{
	zval *zobject = getThis();
	swEventData buf;
	long timeout = SW_TASKWAIT_TIMEOUT;
	char *data;
	int data_len;

	if (zobject == NULL)
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os|l", &zobject, swoole_server_class_entry_ptr, &data, &data_len, &timeout) == FAILURE)
		{
			return;
		}
	}
	else
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &data, &data_len, &timeout) == FAILURE)
		{
			return;
		}
	}

	if(data_len > sizeof(buf.data))
	{
		swWarn("SwooleServer: task data max_size=%d.", sizeof(buf.data));
		RETURN_FALSE;
	}

	memcpy(buf.data, data, data_len);
	buf.info.len = data_len;
	buf.info.type = SW_TASK_BLOCKING;
	//使用fd保存task_id
	buf.info.fd = php_swoole_task_id++;
	//from_id保存worker_id
	buf.info.from_id = SwooleWG.id;

	if (swProcessPool_dispatch(&SwooleG.task_workers, &buf) > 0)
	{
		int ret = 0;
		uint64_t notify;
		swSetTimeout(SwooleG.task_notify[SwooleWG.id].getFd(&SwooleG.task_notify[SwooleWG.id], 0), timeout);
		do
		{
			ret = SwooleG.task_notify[SwooleWG.id].read(&SwooleG.task_notify[SwooleWG.id], &notify, sizeof(notify));
		} while (ret < 0 && errno == EINTR);

		if (ret > 0)
		{
			RETURN_STRINGL(SwooleG.task_result[SwooleWG.id].data, SwooleG.task_result[SwooleWG.id].info.len, 1);
		}
		else
		{
			zend_error(E_WARNING, "taskwait fail. Error: %s[%d]", strerror(errno), errno);
		}
	}
	RETURN_FALSE;

}

PHP_FUNCTION(swoole_server_task)
{
	zval *zobject = getThis();
	swEventData buf;
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

	if(data_len > sizeof(buf.data))
	{
		swWarn("SwooleServer: task data max_size=%d.", sizeof(buf.data));
		RETURN_FALSE;
	}

	memcpy(buf.data, data, data_len);
	buf.info.len = data_len;
	buf.info.type = SW_TASK_NONBLOCK;
	//使用fd保存task_id
	buf.info.fd = php_swoole_task_id++;
	//from_id保存worker_id
	buf.info.from_id = SwooleWG.id;

	if (swProcessPool_dispatch(&SwooleG.task_workers, &buf) > 0)
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
	swEventData buf;
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
	if(data_len > sizeof(buf.data))
	{
		swWarn("SwooleServer: finish data max_size=%d.", sizeof(buf.data));
		RETURN_FALSE;
	}
	SWOOLE_GET_SERVER(zobject, serv);
	if(serv->task_worker_num < 1)
	{
		swWarn("SwooleServer: finish can not use here");
		RETURN_FALSE;
	}
	swFactory *factory = &serv->factory;

	//for swoole_server_task
	if (sw_current_task->info.type == SW_TASK_NONBLOCK)
	{
		memcpy(buf.data, data, data_len);
		buf.info.len = data_len;
		buf.info.type = SW_EVENT_FINISH;
		buf.info.fd = sw_current_task->info.fd;
		SW_CHECK_RETURN(swFactoryProcess_send2worker(factory, &buf, sw_current_task->info.from_id));
	}
	else
	{
		uint64_t flag = 1;
		int ret;
		swEventData *result = &SwooleG.task_result[sw_current_task->info.from_id];
		memcpy(result->data, data, data_len);
		result->info.len = data_len;
		result->info.type = SW_EVENT_FINISH;
		result->info.fd = sw_current_task->info.fd;
		do
		{
			ret = SwooleG.task_notify[sw_current_task->info.from_id].write(&SwooleG.task_notify[sw_current_task->info.from_id], &flag, sizeof(flag));
		}
		while(ret < 0 && (errno==EINTR || errno==EAGAIN));
	}
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
