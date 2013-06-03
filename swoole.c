/*
 +----------------------------------------------------------------------+
 | PHP Version 5                                                        |
 +----------------------------------------------------------------------+
 | Copyright (c) 1997-2012 The PHP Group                                |
 +----------------------------------------------------------------------+
 | This source file is subject to version 3.01 of the PHP license,      |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.php.net/license/3_01.txt                                  |
 | If you did not receive a copy of the PHP license and are unable to   |
 | obtain it through the world-wide-web, please send a note to          |
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author:                                                              |
 +----------------------------------------------------------------------+
 */

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_swoole.h"
#include "swoole.h"
#include "Server.h"
#include "Client.h"

/* If you declare any globals in php_swoole.h uncomment this:
 ZEND_DECLARE_MODULE_GLOBALS(swoole)
 */

#ifdef ZTS
#define TSRMLS_FETCH_FROM_CTX(ctx)  void ***tsrm_ls = (void ***) ctx
#define TSRMLS_SET_CTX(ctx)     ctx = (void ***) tsrm_ls
#else
#define TSRMLS_FETCH_FROM_CTX(ctx)
#define TSRMLS_SET_CTX(ctx)
#endif

/* True global resources - no need for thread safety here */

#define SW_RES_SERVER_NAME          "SwooleServer"
#define SW_RES_CLIENT_NAME          "SwooleClient"

#define PHP_CALLBACK_NUM  6

#define PHP_CB_onStart          0
#define PHP_CB_onConnect        1
#define PHP_CB_onReceive        2
#define PHP_CB_onClose          3
#define PHP_CB_onShutdown       4
#define PHP_CB_onTimer          5
#define SW_HOST_SIZE            64

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_create, 0, 1, 3)
	ZEND_ARG_INFO(0, serv_host)
	ZEND_ARG_INFO(0, serv_port)
	ZEND_ARG_INFO(0, serv_mode)
	ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

static int le_swoole_server;
static int le_swoole_client;

static zval *php_sw_callback[PHP_CALLBACK_NUM];
static void ***sw_thread_ctx;

static int php_swoole_onReceive(swFactory *, swEventData *);
static void php_swoole_onStart(swServer *);
static void php_swoole_onShutdown(swServer *);
static void php_swoole_onConnect(swServer *, int fd, int from_id);
static void php_swoole_onClose(swServer *, int fd, int from_id);
static void php_swoole_onTimer(swServer *serv, int interval);
static void sw_destory_server(zend_rsrc_list_entry *rsrc TSRMLS_DC);
static void sw_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC);

const zend_function_entry swoole_functions[] =
{
	PHP_FE(swoole_server_create, arginfo_swoole_server_create)
	PHP_FE(swoole_server_set, NULL)
	PHP_FE(swoole_server_start, NULL)
	PHP_FE(swoole_server_send, NULL)
	PHP_FE(swoole_server_close, NULL)
	PHP_FE(swoole_server_handler, NULL)
	PHP_FE(swoole_server_addlisten, NULL)
	PHP_FE(swoole_server_addtimer, NULL)
	PHP_FE(swoole_server_reload, NULL)

	PHP_FE_END /* Must be the last line in swoole_functions[] */
};

const zend_function_entry swoole_client_methods[] =
{
	PHP_ME(swoole_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(swoole_client, connect, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, recv, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, send, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, close, NULL, ZEND_ACC_PUBLIC)

	PHP_FE_END /* Must be the last line in swoole_client_methods[] */
};

static zend_class_entry swoole_client_ce;
static zend_class_entry *swoole_client_class_entry_ptr;

zend_module_entry swoole_module_entry =
{
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"swoole",
	swoole_functions,
	PHP_MINIT(swoole),
	PHP_MSHUTDOWN(swoole),
	PHP_RINIT(swoole), /* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(swoole), /* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(swoole),
#if ZEND_MODULE_API_NO >= 20010901
		"0.1", /* Replace with version number for your extension */
#endif
		STANDARD_MODULE_PROPERTIES };
/* }}} */

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
	/* If you have INI entries, uncomment these lines 
	 REGISTER_INI_ENTRIES();
	 */
	le_swoole_server = zend_register_list_destructors_ex(sw_destory_server, NULL, SW_RES_SERVER_NAME, module_number);
	le_swoole_client = zend_register_list_destructors_ex(sw_destory_client, NULL, SW_RES_CLIENT_NAME, module_number);

	REGISTER_LONG_CONSTANT("SWOOLE_BASE", SW_MODE_CALL, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_THREAD", SW_MODE_THREAD, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", SW_MODE_PROCESS, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_SYNC", SW_SOCK_SYNC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_SOCK_ASYNC", SW_SOCK_ASYNC, CONST_CS | CONST_PERSISTENT);

	INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", swoole_client_methods);
	swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(swoole)
{
	/* uncomment this line if you have INI entries
	 UNREGISTER_INI_ENTRIES();
	 */
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(swoole)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(swoole)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(swoole)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "swoole support", "enabled");
	php_info_print_table_row(2, "Version", "1.4.1");
	php_info_print_table_row(2, "Author", "tianfeng.han[email: mikan.tenny@gmail.com]");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	 DISPLAY_INI_ENTRIES();
	 */
}
/* }}} */

static void sw_destory_server(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	swServer *serv = (swServer *) rsrc->ptr;
	swServer_free(serv);
	sw_free(serv);
}

static void sw_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	swClient *cli = (swClient *) rsrc->ptr;
	if(cli->sock != 0)
	{
		cli->close(cli);
	}
	efree(cli);
}

PHP_FUNCTION(swoole_server_create)
{
	swServer *serv = sw_malloc(sizeof(swServer));
	int host_len;
	char *serv_host;
	long sock_type = SW_SOCK_TCP;
	long serv_port;
	long serv_mode;

	swServer_init(serv);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll|l", &serv_host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
	{
		return;
	}
	serv->factory_mode = (int)serv_mode;
	swTrace("Create host=%s,port=%ld,mode=%d\n", serv_host, serv_port, serv->factory_mode); 
	TSRMLS_SET_CTX(sw_thread_ctx);

	if(swServer_addListen(serv, sock_type, serv_host, serv_port) < 0) {
		zend_error(E_ERROR, "swServer_addListen fail. errno=%d.", errno);
	}
	ZEND_REGISTER_RESOURCE(return_value, serv, le_swoole_server);
}

PHP_FUNCTION(swoole_server_set)
{
	zval *zset = NULL;
	zval *zserv = NULL;
	HashTable * vht;
	swServer *serv;
	zval **v;
	double timeout;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ra", &zserv, &zset ) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	serv->ptr2 = zserv;
	zval_add_ref(&zserv);

	vht = Z_ARRVAL_P(zset);
	//timeout
	if (zend_hash_find(vht, ZEND_STRS("timeout"), (void **)&v) == SUCCESS)
	{
		timeout = Z_DVAL_PP(v);
		serv->timeout_sec = (int)timeout;
		serv->timeout_usec = (int)((timeout*1000*1000) - (serv->timeout_sec*1000*1000));
	}
	//daemonize，守护进程化
	if (zend_hash_find(vht, ZEND_STRS("daemonize"), (void **)&v) == SUCCESS)
	{
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
		serv->poll_thread_num = (int)Z_LVAL_PP(v);
	}
	//writer_num
	if (zend_hash_find(vht, ZEND_STRS("writer_num"), (void **)&v) == SUCCESS)
	{
		serv->writer_num = (int)Z_LVAL_PP(v);
	}
	//writer_num
	if (zend_hash_find(vht, ZEND_STRS("worker_num"), (void **)&v) == SUCCESS)
	{
		serv->worker_num = (int)Z_LVAL_PP(v);
	}
	//max_conn
	if (zend_hash_find(vht, ZEND_STRS("max_conn"), (void **)&v) == SUCCESS)
	{
		serv->max_conn = (int)Z_LVAL_PP(v);
	}
	//max_request
	if (zend_hash_find(vht, ZEND_STRS("max_request"), (void **)&v) == SUCCESS)
	{
		serv->max_request = (int)Z_LVAL_PP(v);
	}
	//cpu affinity
	if (zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **)&v) == SUCCESS)
	{
		serv->open_cpu_affinity = (char)Z_LVAL_PP(v);
	}
	//tcp nodelay
	if (zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **)&v) == SUCCESS)
	{
		serv->open_tcp_nodelay = (char)Z_LVAL_PP(v);
	}
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_handler)
{
	zval *zserv = NULL;
	char *ha_name = NULL;
	int len;
	swServer *serv;
	zval *cb;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz", &zserv, &ha_name, &len, &cb) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);

	//add ref
	zval_add_ref(&cb);

	if(strncasecmp("onStart", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onStart] = cb;
	}
	else if(strncasecmp("onConnect", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onConnect] = cb;
	}
	else if(strncasecmp("onReceive", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onReceive] = cb;
	}
	else if(strncasecmp("onClose", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onClose] = cb;
	}
	else if(strncasecmp("onShutdown", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onShutdown] = cb;
	}
	else if(strncasecmp("onTimer", ha_name, len) == 0)
	{
		php_sw_callback[PHP_CB_onTimer] = cb;
	}
	else
	{
		zend_error(E_ERROR, "swoole_server_handler: unkown handler[%s].", ha_name);
	}
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_close)
{
	zval *zserv = NULL;
	swServer *serv;
	swEvent ev;
	long conn_fd, from_id = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl|l", &zserv, &conn_fd, &from_id) == FAILURE)
	{
		return;
	}
	//zserv resource
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	if(from_id < 0)
	{
		ev.from_id = serv->factory.last_from_id;
	}
	else
	{
		ev.from_id = (int)from_id;
	}
	ev.fd = (int)conn_fd;
	SW_CHECK_RETURN(swServer_close(serv, &ev));
}

PHP_FUNCTION(swoole_server_reload)
{
	zval *zserv = NULL;
	swServer *serv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zserv) == FAILURE)
	{
		return;
	}
	//zserv resource
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	SW_CHECK_RETURN(swServer_reload(serv));
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

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, req->fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, req->from_id);

	MAKE_STD_ZVAL(zdata);
	ZVAL_STRINGL(zdata, req->data, req->len, 0);

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;
	args[3] = &zdata;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onReceive], &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwoolServer: onReceive handler error");
	}
	return SW_OK;
}

void php_swoole_onStart(swServer *serv)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onStart], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwooleServer: onStart handler error");
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

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onTimer], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwooleServer: onTimer handler error");
	}
}

void php_swoole_onShutdown(swServer *serv)
{
	zval *zserv = (zval *)serv->ptr2;
	zval **args[1];
	zval *retval;

	args[0] = &zserv;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onShutdown], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwooleServer: onShutdown handler error");
	}
}

void php_swoole_onConnect(swServer *serv, int fd, int from_id)
{
	zval *zserv = (zval *)serv->ptr2;
	zval *zfd;
	zval *zfrom_id;
	zval **args[3];
	zval *retval;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, from_id);

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onConnect], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwooleServer: onConnect handler error");
	}
}

void php_swoole_onClose(swServer *serv, int fd, int from_id)
{
	zval *zserv = (zval *)serv->ptr2;
	zval *zfd;
	zval *zfrom_id;
	zval **args[3];
	zval *retval;

	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, fd);

	MAKE_STD_ZVAL(zfrom_id);
	ZVAL_LONG(zfrom_id, from_id);

	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zfrom_id;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, php_sw_callback[PHP_CB_onClose], &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "SwooleServer: onClose handler error");
	}
}

PHP_FUNCTION(swoole_server_start)
{
	zval *zserv = NULL;
	swServer *serv;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zserv) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);

	serv->onClose = php_swoole_onClose;
	serv->onStart = php_swoole_onStart;
	serv->onShutdown = php_swoole_onShutdown;
	serv->onConnect = php_swoole_onConnect;
	serv->onReceive = php_swoole_onReceive;
	serv->onTimer  = php_swoole_onTimer;

	ret = swServer_create(serv);
	if (ret < 0)
	{
		zend_error(E_ERROR, "create server fail[errno=%d].\n", ret);
		RETURN_LONG(ret);
	}
	ret = swServer_start(serv);
	if (ret < 0)
	{
		zend_error(E_ERROR, "start server fail[errno=%d].\n", ret);
		RETURN_LONG(ret);
	}
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_server_send)
{
	zval *zserv = NULL;
	swServer *serv = NULL;
	swFactory *factory = NULL;
	swSendData send_data;
	int ret;
	long conn_fd;
	long from_id = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rls|l", &zserv, &send_data.fd, &send_data.data, &send_data.len, &from_id) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	factory = &(serv->factory);
	if(from_id < 0)
	{
		send_data.from_id = factory->last_from_id;
	}
	else
	{
		send_data.from_id = (int)from_id;
	}
	SW_CHECK_RETURN(factory->finish(factory, &send_data));
}

PHP_FUNCTION(swoole_server_addlisten)
{
	zval *zserv = NULL;
	swServer *serv = NULL;
	swFactory *factory = NULL;
	char *host;
	int host_len;
	long sock_type;
	long port;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsll", &zserv, &host, &host_len, &port, &sock_type) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	SW_CHECK_RETURN(swServer_addListen(serv, (int)sock_type, host, (int)port));
}

PHP_FUNCTION(swoole_server_addtimer)
{
	zval *zserv = NULL;
	swServer *serv = NULL;
	swFactory *factory = NULL;
	long interval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &zserv, &interval) == FAILURE)
	{
		return;
	}
	ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);
	SW_CHECK_RETURN(swServer_addTimer(serv, (int)interval));
}

PHP_METHOD(swoole_client, __construct)
{
	long type, async = 0;
	zval *zres;

	if ( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &type, &async ) == FAILURE ) {
		RETURN_FALSE;
	}

	swClient *cli = (swClient*) emalloc(sizeof(swClient));
	if(swClient_create(cli, type, async) < 0)
	{
		zend_error(E_WARNING, "swClient_create fail. errno=%d", errno);
		RETURN_FALSE;
	}
	MAKE_STD_ZVAL(zres);

	ZEND_REGISTER_RESOURCE(zres, cli, le_swoole_client);
	zend_hash_update(Z_OBJPROP_P(getThis()), "_client", sizeof("_client"), &zres, sizeof(zres), NULL);
	RETURN_TRUE;
}

PHP_METHOD(swoole_client, connect)
{
	int ret;
	long port, udp_connect;
	char *host;
	int host_len;
	double timeout;

	zval **zres;
	swClient *cli = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|dl", &host, &host_len, &port, &timeout, &udp_connect) == FAILURE) {
			return;
	}
	if(zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **)&zres) == SUCCESS) {
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	} else {
		RETURN_FALSE;
	}
	ret = cli->connect(cli, host, port, (float)timeout, udp_connect);
	if(ret < 0)	{
		zend_error(E_WARNING, "connect server fail[errno=%d].\n", ret);
		RETURN_FALSE;
	} else {
		RETURN_TRUE;
	}
}

PHP_METHOD(swoole_client, send)
{
	int ret;
	char *data;
	int data_len;

	zval **zres;
	swClient *cli;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
			return;
	}
	if(zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **)&zres) == SUCCESS) {
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	} else {
		RETURN_FALSE;
	}
	ret = cli->send(cli, data, data_len);
	if(ret < 0)	{
		zend_error(E_WARNING, "connect server fail[errno=%d].\n", ret);
		RETURN_FALSE;
	} else {
		RETURN_LONG(ret);
	}
}

PHP_METHOD(swoole_client, recv)
{
	long data_len, waitall = 0;
	zval **zres;
	//zval *zdata;
	int ret;
	swClient *cli;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &data_len, &waitall) == FAILURE) {
			return;
	}
	if(zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **)&zres) == SUCCESS) {
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	} else {
		RETURN_FALSE;
	}
	char *buf = emalloc(data_len);

	if((ret = cli->recv(cli, buf, data_len, waitall)) < 0) {
		zend_error(E_WARNING, "swClient recv fail.errno=%d", errno);
		efree(buf);
		RETURN_FALSE;
	} else {
		RETURN_STRING(buf, 0);
	}
}

PHP_METHOD(swoole_client, close)
{
	zval **zres;
	swClient *cli;

	if(zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **)&zres) == SUCCESS) {
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	} else {
		RETURN_FALSE;
	}

	if(cli->close(cli) < 0)	{
		RETURN_FALSE;
	} else {
		RETURN_TRUE;
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
