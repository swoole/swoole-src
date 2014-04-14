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

#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"

#include "ext/standard/basic_functions.h"

#ifdef SW_SOCKETS
#if PHP_VERSION_ID >= 50301 && (HAVE_SOCKETS || defined(COMPILE_DL_SOCKETS))
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#else
#error "Enable sockets support, But no sockets extension"
#endif
#endif

#define php_sw_client_onConnect     "onConnect"
#define php_sw_client_onReceive     "onReceive"
#define php_sw_client_onClose       "onClose"
#define php_sw_client_onError       "onError"

typedef struct {
	zval *callback;
	zval *socket;
} swoole_reactor_fd;

typedef struct {
	zval *callback;
	int interval;
} swoole_timer_item;

char php_sw_reactor_wait_onexit = 0;
static char php_sw_reactor_ok = 0;
static char php_sw_in_client = 0;
static char php_sw_event_wait = 0;

static char *php_sw_callbacks[PHP_CLIENT_CALLBACK_NUM] =
{
	php_sw_client_onConnect,
	php_sw_client_onReceive,
	php_sw_client_onClose,
	php_sw_client_onError,
};

HashTable php_sw_long_connections;

static int php_swoole_client_event_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC);
static int php_swoole_client_event_loop(zval *sock_array, fd_set *fds TSRMLS_DC);
static int php_swoole_client_close(zval **zobject, int fd TSRMLS_DC);
static int php_swoole_onReactorCallback(swReactor *reactor, swEvent *event);
static void php_swoole_onTimerCallback(swTimer *timer, int interval);

static int php_swoole_client_onReceive(swReactor *reactor, swEvent *event);
static int php_swoole_client_onConnect(swReactor *reactor, swEvent *event);

static int swoole_convert_to_fd(zval **fd);
static swClient* swoole_client_create_socket(zval *object, char *host, int host_len, int port);

/**
 * @zobject: swoole_client object
 */
static int php_swoole_client_close(zval **zobject, int fd TSRMLS_DC)
{
	zval *zcallback = NULL;
	zval *retval;
	zval **args[1];
	swClient *cli;

	char *hash_key;
	int hash_key_len;

	zval **zres;
	if (zend_hash_find(Z_OBJPROP_PP(zobject), SW_STRL("_client"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE_NO_RETURN(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	}
	else
	{
		zend_error(E_WARNING, "swoole_client->close[1]: no _client property.");
		return SW_ERR;
	}

	//async connection
	if (cli->async)
	{

		//remove from reactor
		if (SwooleG.main_reactor)
		{
			SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
		}

		hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", fd);
		if (zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len+1, (void **)&zobject) != SUCCESS)
		{
			zend_error(E_WARNING, "swoole_client->close[2]: Fd[%d] is not a swoole_client object", fd);
			fatal_error:
			efree(hash_key);
			return SW_ERR;
		}

		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL(php_sw_client_onClose)-1, 0 TSRMLS_CC);
		if (ZVAL_IS_NULL(zcallback))
		{
			zend_error(E_WARNING, "swoole_client->close[3]: no close callback.");
			goto fatal_error;
		}

		args[0] = zobject;
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client->close[4]: onClose handler error");
			goto fatal_error;
		}

		if (SwooleG.main_reactor->event_num == 0 && php_sw_in_client == 1)
		{
			SwooleG.running = 0;
		}

		if (zend_hash_del(&php_sw_client_callback, hash_key, hash_key_len+1) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client: del from client callback hashtable failed.");
		}

		//hashtable key
		efree(hash_key);

		//free the callback return value
		if (retval != NULL)
		{
			zval_ptr_dtor(&retval);
		}
	}
	else
	{
		cli->close(cli);
	}

	//long tcp connection, clear from php_sw_long_connections
	zval *ztype = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL("type")-1, 0 TSRMLS_CC);
	if (ZVAL_IS_NULL(ztype))
	{
		zend_error(E_WARNING, "get swoole_client->type failed.");
	}
	else if (Z_LVAL_P(ztype) & SW_FLAG_KEEP)
	{
		if (zend_hash_del(&php_sw_long_connections, cli->server_str, cli->server_strlen) == SUCCESS)
		{
			zend_error(E_WARNING, "swoole_client_create_socket add to hashtable failed.");
		}
		free(cli->server_str);
		pefree(cli, 1);
	}
	else
	{
		free(cli->server_str);
		efree(cli);
	}
	return SW_OK;
}

static int php_swoole_client_onReceive(swReactor *reactor, swEvent *event)
{
	int n;
	zval **zobject, *zcallback = NULL;
	zval **args[2];
	zval *retval;

	char *hash_key;
	int hash_key_len;
	hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", event->fd);

	if(zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len+1, (void **)&zobject) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_client: Fd[%d] is not a swoole_client object", event->fd);
		efree(hash_key);
		return SW_ERR;
	}

	args[0] = zobject;
	char buf[SW_CLIENT_BUFFER_SIZE];
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd, buf, SW_CLIENT_BUFFER_SIZE);
#else
	//非ET模式会持续通知
	n = recv(event->fd, buf, SW_CLIENT_BUFFER_SIZE, 0);
#endif

	if (n < 0)
	{
		if (swConnection_error(event->fd, errno) == SW_ERR)
		{
			goto close_fd;
		}
		else
		{
			swWarn("Read from socket[%d] fail. Error: %s [%d]", event->fd, strerror(errno), errno);
			efree(hash_key);
			return SW_ERR;
		}
	}
	else if (n == 0)
	{
		close_fd:
		efree(hash_key);
		return php_swoole_client_close(zobject, event->fd TSRMLS_CC);
	}
	else
	{
		zval *zdata;
		MAKE_STD_ZVAL(zdata);
		ZVAL_STRINGL(zdata, buf, n, 1);

		args[1] = &zdata;

		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL(php_sw_client_onReceive)-1, 0 TSRMLS_CC);
		if (ZVAL_IS_NULL(zcallback))
		{
			zend_error(E_WARNING, "swoole_client: swoole_client object have not receive callback.");
			efree(hash_key);
			return SW_ERR;
		}
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_server: onReactorCallback handler error");
			efree(hash_key);
			return SW_ERR;
		}
		zval_ptr_dtor(&zdata);
		if (retval != NULL)
		{
			zval_ptr_dtor(&retval);
		}
	}
	efree(hash_key);
	return SW_OK;
}

static int php_swoole_client_onConnect(swReactor *reactor, swEvent *event)
{
	zval **zobject = NULL, *zcallback = NULL;
	zval **args[1];
	zval *retval;

	char *hash_key;
	int hash_key_len;
	hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", event->fd);

	if(zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len+1, (void **)&zobject) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_client->onConnect: Fd=%d is not a swoole_client object", event->fd);
		efree(hash_key);
		return SW_ERR;
	}
	args[0] = zobject;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	int error;
	socklen_t len = sizeof(error);

	if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
	{
		zend_error(E_WARNING, "swoole_client: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
		efree(hash_key);
		return SW_ERR;
	}
	//success
	if(error == 0)
	{
		zval **zres;
		swClient *cli;
		SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, (SW_FD_USER+1) | SW_EVENT_READ);

		if (zend_hash_find(Z_OBJPROP_PP(zobject), SW_STRL("_client"), (void **) &zres) == SUCCESS)
		{
			ZEND_FETCH_RESOURCE_NO_RETURN(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
			cli->connected = 1;
		}
		else
		{
			return SW_ERR;
		}

		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL(php_sw_client_onConnect)-1, 0 TSRMLS_CC);
		if (ZVAL_IS_NULL(zcallback))
		{
			zend_error(E_WARNING, "swoole_client: swoole_client object have not connect callback.");
			efree(hash_key);
			return SW_ERR;
		}
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client: onConnect handler error");
			efree(hash_key);
			return SW_ERR;
		}
		if (retval)
		{
			zval_ptr_dtor(&retval);
		}
	}
	else
	{
		zend_error(E_WARNING, "swoole_client: connect to server fail. Error: %s [%d]", strerror(error), error);
		SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL(php_sw_client_onError)-1, 0 TSRMLS_CC);

		zval *errCode;
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, error);
		zend_update_property(swoole_client_class_entry_ptr, *zobject, ZEND_STRL("errCode"), errCode TSRMLS_CC);

		if (ZVAL_IS_NULL(zcallback))
		{
			zend_error(E_WARNING, "swoole_client: swoole_client object have not error callback.");
			efree(hash_key);
			return SW_ERR;
		}
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client: onError handler error");
			efree(hash_key);
			return SW_ERR;
		}
		zval_ptr_dtor(&errCode);
		if (retval)
		{
			zval_ptr_dtor(&retval);
		}
	}
	return SW_OK;
}

void php_swoole_check_reactor()
{
	if(php_sw_reactor_ok == 0)
	{
		if (SwooleG.main_reactor == NULL)
		{
			SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
			if(SwooleG.main_reactor == NULL)
			{
				zend_error(E_ERROR, "swoole_client: malloc SwooleG.main_reactor failed.");
				return;
			}
			if (swReactor_auto(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
			{
				zend_error(E_ERROR, "swoole_client: create SwooleG.main_reactor failed.");
				return;
			}
			//client, swoole_event_exit will set swoole_running = 0
			php_sw_in_client = 1;
		}
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER+1) | SW_EVENT_WRITE, php_swoole_client_onConnect);
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER+1), php_swoole_client_onReceive);

		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER, php_swoole_onReactorCallback);

		php_sw_reactor_ok = 1;
	}
	return;
}

static void php_swoole_onTimerCallback(swTimer *timer, int interval)
{
	zval *retval;
	zval **args[1];
	swoole_timer_item *timer_item;

	if(zend_hash_find(&php_sw_timer_callback, (char *)&interval, sizeof(interval), (void**)&timer_item) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_timer: onReactorCallback not found");
		return;
	}

	zval *zinterval;
	MAKE_STD_ZVAL(zinterval);
	ZVAL_LONG(zinterval, interval);

	args[0] = &zinterval;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, timer_item->callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "swoole_timer: onReactorCallback handler error");
		return;
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	zval_ptr_dtor(&zinterval);
}

static int php_swoole_onReactorCallback(swReactor *reactor, swEvent *event)
{
	zval *retval;
	zval **args[1];
	swoole_reactor_fd *fd;

	if(zend_hash_find(&php_sw_reactor_callback, (char *)&(event->fd), sizeof(event->fd), (void**)&fd) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_server: onReactorCallback not found");
		return SW_ERR;
	}

	args[0] = &fd->socket;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, fd->callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "swoole_server: onReactorCallback handler error");
		return SW_ERR;
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}


void php_swoole_try_run_reactor()
{
	//only client side
	if (php_sw_in_client == 1 && php_sw_reactor_wait_onexit == 0)
	{
		TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

		zval *callback;
		MAKE_STD_ZVAL(callback);

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4

		php_shutdown_function_entry shutdown_function_entry;

		shutdown_function_entry.arg_count = 1;
	    shutdown_function_entry.arguments = (zval **) safe_emalloc(sizeof(zval *), 1, 0);

		ZVAL_STRING(callback, "swoole_event_wait", 1);
		shutdown_function_entry.arguments[0] = callback;

		if (!register_user_shutdown_function("swoole_event_wait", sizeof("swoole_event_wait"), &shutdown_function_entry TSRMLS_CC))
		{
			efree(shutdown_function_entry.arguments);
			zval_ptr_dtor(&callback);
			zend_error(E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
		}
#else
		zend_error(E_WARNING, "swoole_client: PHP%d.%d not support auto run swoole_event_wait. Please append swoole_event_wait at the script end.", PHP_MAJOR_VERSION, PHP_MINOR_VERSION);
#endif
		php_sw_reactor_wait_onexit = 1;
		php_sw_event_wait = 0;
	}
}

static swClient* swoole_client_create_socket(zval *object, char *host, int host_len, int port)
{
	zval *ztype, *zres, *zsockfd, *zerrorCode;
	int async = 0;
	swClient *cli;
	char conn_key[SW_LONG_CONNECTION_KEY_LEN];
	int conn_key_len = 0;
	uint64_t tmp_buf;
	int ret;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	ztype = zend_read_property(swoole_client_class_entry_ptr, object, SW_STRL("type")-1, 0 TSRMLS_CC);

	if (ZVAL_IS_NULL(ztype))
	{
		zend_error(E_ERROR, "get swoole_client->type failed.");
		return NULL;
	}

	long type = Z_LVAL_P(ztype);
	bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);
	conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s:%d", host, port) + 1;

	//new flag, swoole-1.6.12+
	if(type & SW_FLAG_ASYNC)
	{
		async = 1;
	}

	//keep the tcp connection
	if (type & SW_FLAG_KEEP)
	{
		swClient **find;
		if (zend_hash_find(&php_sw_long_connections, conn_key, conn_key_len, (void **) &find) == FAILURE)
		{
			cli = (swClient*) pemalloc(sizeof(swClient), 1);
			if (zend_hash_update(&php_sw_long_connections, conn_key, conn_key_len, &cli, sizeof(cli), NULL) == FAILURE)
			{
				zend_error(E_WARNING, "swoole_client_create_socket add to hashtable failed.");
			}
			goto create_socket;
		}
		else
		{
			cli = *find;
			//try recv, check connection status
			ret = recv(cli->sock, &tmp_buf, sizeof(tmp_buf), MSG_DONTWAIT | MSG_PEEK);
			if (ret == 0 || (ret < 0 && swConnection_error(cli->sock, errno) == SW_ERR))
			{
                
				cli->close(cli);
				goto create_socket;
			}
		}
	}
	else
	{
		cli = (swClient*) emalloc(sizeof(swClient));

		create_socket:
		if (swClient_create(cli, php_swoole_socktype(type), async) < 0)
		{
			zend_error(E_WARNING, "swoole_client: create failed. Error: %s [%d]", strerror(errno), errno);
			MAKE_STD_ZVAL(zerrorCode);
			ZVAL_LONG(zerrorCode, errno);
			zend_update_property(swoole_client_class_entry_ptr, object, ZEND_STRL("errCode"), zerrorCode TSRMLS_CC);
			return NULL;
		}
		//don't forget free it
		cli->server_str = strdup(conn_key);
		cli->server_strlen = conn_key_len;
	}

	MAKE_STD_ZVAL(zres);
	MAKE_STD_ZVAL(zsockfd);
	ZVAL_LONG(zsockfd, cli->sock);

	ZEND_REGISTER_RESOURCE(zres, cli, le_swoole_client);

	zend_update_property(swoole_client_class_entry_ptr, object, ZEND_STRL("sock"), zsockfd TSRMLS_CC);
	zend_update_property(swoole_client_class_entry_ptr, object, ZEND_STRL("_client"), zres TSRMLS_CC);

	zval_ptr_dtor(&zres);
	zval_ptr_dtor(&zsockfd);

	if (type & SW_FLAG_KEEP)
	{
		cli->keep = 1;
	}
	return cli;
}

static int swoole_convert_to_fd(zval **fd)
{
	php_stream *stream;
	int socket_fd;

	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

#ifdef SWOOLE_SOCKETS_SUPPORT
	php_socket *php_sock;
#endif
	if (Z_TYPE_PP(fd) == IS_RESOURCE)
	{
		if (ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream *, fd, -1, NULL, php_file_le_stream()))
		{
			if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1)
					!= SUCCESS || socket_fd < 0)
			{
				return SW_ERR;
			}
		}
		else
		{
#ifdef SWOOLE_SOCKETS_SUPPORT
			if (ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket *, fd, -1, NULL, php_sockets_le_socket()))
			{
				socket_fd = php_sock->bsd_socket;

			}
			else
			{
				zend_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
				return SW_ERR;
			}
#else
			zend_error(E_WARNING, "fd argument must be valid PHP stream resource");
			return SW_ERR;
#endif
		}
	}
	else if (Z_TYPE_PP(fd) == IS_LONG)
	{
		socket_fd = Z_LVAL_PP(fd);
		if (socket_fd < 0)
		{
			zend_error(E_WARNING, "invalid file descriptor passed");
			return SW_ERR;
		}
	}
	else
	{
		return SW_ERR;
	}
	return socket_fd;
}

PHP_FUNCTION(swoole_timer_add)
{
	swoole_timer_item timer_item;
	long interval;

	if (swIsMaster())
	{
		zend_error(E_WARNING, "swoole_timer_add can not use in swoole_server. Please use swoole_server->addtimer");
		RETURN_FALSE;
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &interval, &timer_item.callback) == FAILURE)
	{
		return;
	}

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	zval_add_ref(&timer_item.callback);
	timer_item.interval = (int)interval;

	if(zend_hash_update(&php_sw_timer_callback, (char *)&timer_item.interval, sizeof(timer_item.interval), &timer_item, sizeof(swoole_timer_item), NULL) == FAILURE)
	{
		zend_error(E_WARNING, "swoole_timer_add add to hashtable failed.");
		RETURN_FALSE;
	}
	php_swoole_check_reactor();

	if (SwooleG.timer.fd == 0)
	{
		if(swTimer_create(&SwooleG.timer, timer_item.interval) < 0)
		{
			RETURN_FALSE;
		}
		SwooleG.timer.onTimer = php_swoole_onTimerCallback;
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_TIMER, swTimer_event_handler);
		SwooleG.main_reactor->add(SwooleG.main_reactor, SwooleG.timer.fd, SW_FD_TIMER);
	}

	if (swTimer_add(&SwooleG.timer, timer_item.interval) < 0)
	{
		RETURN_FALSE;
	}

	php_swoole_try_run_reactor();
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_timer_del)
{
	long interval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &interval) == FAILURE)
	{
		return;
	}
	if (SwooleG.timer.fd == 0)
	{
		zend_error(E_WARNING, "no timer.");
		RETURN_FALSE;
	}
	swTimer_del(&SwooleG.timer, (int)interval);
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_add)
{
	zval *cb;
	zval **fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Zz", &fd, &cb) == FAILURE)
	{
		return;
	}

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	int socket_fd = swoole_convert_to_fd(fd);
	if(socket_fd < 0)
	{
		zend_error(E_WARNING, "unknow type.");
		RETURN_FALSE;
	}

	swoole_reactor_fd event;
	event.socket = *fd;
	event.callback = cb;
	zval_add_ref(&event.socket);
	zval_add_ref(&event.callback);

	if(zend_hash_update(&php_sw_reactor_callback, (char *)&socket_fd, sizeof(socket_fd), &event, sizeof(swoole_reactor_fd), NULL) == FAILURE)
	{
		zend_error(E_WARNING, "swoole_event_add add to hashtable failed");
		RETURN_FALSE;
	}
	php_swoole_check_reactor();
	swSetNonBlock(socket_fd); //must be nonblock
	if(SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER) < 0)
	{
		zend_error(E_WARNING, "swoole_event_add failed.");
		RETURN_FALSE;
	}
	php_swoole_try_run_reactor();
	RETURN_LONG(socket_fd);
}

PHP_FUNCTION(swoole_event_del)
{
	zval **fd;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z", &fd) == FAILURE)
	{
		return;
	}
	int socket_fd = swoole_convert_to_fd(fd);
	if (socket_fd < 0)
	{
		zend_error(E_WARNING, "unknow type.");
		RETURN_FALSE;
	}
	Z_DELREF_PP(fd);
	SW_CHECK_RETURN(SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd));
}

PHP_FUNCTION(swoole_event_exit)
{
	if (php_sw_in_client == 1)
	{
		//stop reactor
		SwooleG.running = 0;
	}
}

PHP_FUNCTION(swoole_event_wait)
{
	if (php_sw_in_client == 1 && php_sw_event_wait == 0)
	{
		SwooleG.running = 1;
		php_sw_event_wait = 1;

		struct timeval timeo;
		timeo.tv_sec = SW_REACTOR_TIMEO_SEC;
		timeo.tv_usec = SW_REACTOR_TIMEO_USEC;

		int ret = SwooleG.main_reactor->wait(SwooleG.main_reactor, &timeo);
		if(ret < 0)
		{
			zend_error(E_ERROR, "swoole_client: reactor wait fail. Errno: %s [%d]", strerror(errno), errno);
		}
	}
}

PHP_METHOD(swoole_client, __construct)
{
	long async = 0;
	zval *ztype;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &ztype, &async) == FAILURE)
	{
		zend_error(E_ERROR, "swoole_client: require soclet type param.");
		RETURN_FALSE;
	}

#ifdef ZTS
	if(sw_thread_ctx == NULL)
	{
		TSRMLS_SET_CTX(sw_thread_ctx);
	}
#endif

	if (async == 1)
	{
		Z_LVAL_P(ztype) = Z_LVAL_P(ztype) | SW_FLAG_ASYNC;
	}
	zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), ztype TSRMLS_CC);
	RETURN_TRUE;
}

PHP_METHOD(swoole_client, connect)
{
	int ret, i;
	long port, sock_flag = 0;
	char *host;
	int host_len;
	double timeout = 0.1; //默认100ms超时

	zval *errCode;
	zval *callback = NULL;
	swClient *cli = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|dl", &host, &host_len, &port, &timeout,
			&sock_flag) == FAILURE)
	{
		return;
	}
	cli = swoole_client_create_socket(getThis(), host, host_len, port);

	if (cli->async == 1 && (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6))
	{
		//for tcp: nonblock
		//for udp: have udp connect
		sock_flag = 1;
	}

	if (cli->keep != 1 && cli->connected == 1)
	{
		zend_error(E_WARNING, "swoole_client is already connected.");
		RETURN_FALSE;
	}

	ret = cli->connect(cli, host, port, (float) timeout, sock_flag);

	//nonblock async
	if (cli->async == 1)
	{
		//check callback function
		for(i=0; i<PHP_CLIENT_CALLBACK_NUM; i++)
		{
			callback = zend_read_property(swoole_client_class_entry_ptr, getThis(), php_sw_callbacks[i], strlen(php_sw_callbacks[i]), 1 TSRMLS_CC);
			if (ZVAL_IS_NULL(callback))
			{
				zend_error(E_ERROR, "swoole_client->connect: no %s callback.", php_sw_callbacks[i]);
				RETURN_FALSE;
			}
		}

		char *hash_key;
		int hash_key_len;
		int flag = 0;

		hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", cli->sock);
		zval_add_ref(&getThis());

		if (zend_hash_update(&php_sw_client_callback, hash_key, hash_key_len+1, &getThis(), sizeof(zval*), NULL) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client: add to hashtable fail");
			efree(hash_key);
			RETURN_FALSE;
		}

		php_swoole_check_reactor();
		if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
		{
			flag = (SW_FD_USER+1) | SW_EVENT_WRITE;
		}
		else
		{
			flag = (SW_FD_USER+1);

			zval *zcallback = NULL;
			zval **args[1];
			zval *retval;

			args[0] = &getThis();
			zcallback = zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("connect")-1, 0 TSRMLS_CC);
			if (ZVAL_IS_NULL(callback))
			{
				zend_error(E_WARNING, "swoole_client: swoole_client object have not connect callback.");
				efree(hash_key);
				RETURN_FALSE;
			}
			if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
			{
				zend_error(E_WARNING, "swoole_client: onConnect[udp] handler error");
				efree(hash_key);
				RETURN_FALSE;
			}
			if (retval)
			{
				zval_ptr_dtor(&retval);
			}
		}
		ret = SwooleG.main_reactor->add(SwooleG.main_reactor, cli->sock, flag);
		efree(hash_key);
		php_swoole_try_run_reactor();
		SW_CHECK_RETURN(ret);
	}
	else if (ret < 0)
	{
		zend_error(E_WARNING, "swoole_client: connect to server[%s:%d] fail. Error: %s [%d]", host, (int)port, strerror(errno), errno);
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, errno);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
		zval_ptr_dtor(&errCode);
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

PHP_METHOD(swoole_client, send)
{
	char *data;
	int data_len;

	zval **zres;
	zval *errCode;
	swClient *cli;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
	{
		return;
	}
	if (data_len <= 0)
	{
		zend_error(E_WARNING, "swoole_client: data empty.");
		RETURN_FALSE;
	}

	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	}
	else
	{
		zend_error(E_WARNING, "swoole_client: object is not instanceof swoole_client. ");
		RETURN_FALSE;
	}

	if (cli->connected == 0)
	{
		zend_error(E_WARNING, "swoole_client: Server is not connected.");
		RETURN_FALSE;
	}

	//clear errno
	SwooleG.error = 0;

	int ret = cli->send(cli, data, data_len);
    if (ret < 0)
	{
    	SwooleG.error = errno;
		//这里的错误信息没用
		zend_error(E_WARNING, "swoole_client: send failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, SwooleG.error);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
		zval_ptr_dtor(&errCode);
		RETVAL_FALSE;
	}
	else
	{
		RETVAL_TRUE;
	}
}

PHP_METHOD(swoole_client, recv)
{
	long buf_len = SW_PHP_CLIENT_BUFFER_SIZE, waitall = 0;
	char require_efree = 0;
	char buf_array[SW_PHP_CLIENT_BUFFER_SIZE];
	char *buf;
	zval **zres;
	zval *errCode;

	//zval *zdata;
	int ret;
	swClient *cli;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &buf_len, &waitall) == FAILURE)
	{
		return;
	}
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	}
	else
	{
		RETURN_FALSE;
	}
	if (cli->connected == 0)
	{
		zend_error(E_WARNING, "swoole_client: Server is not connected.");
		RETURN_FALSE;
	}
	/**
	 * UDP waitall=0 buf_len小于最大值这3种情况使用栈内存
	 */
	if (cli->type == SW_SOCK_UDP || cli->type == SW_SOCK_UDP6 || waitall == 0 || buf_len < SW_PHP_CLIENT_BUFFER_SIZE)
	{
		buf = buf_array;
		if(buf_len >= SW_PHP_CLIENT_BUFFER_SIZE)  buf_len = SW_PHP_CLIENT_BUFFER_SIZE-1;
	}
	else
	{
		buf = emalloc(buf_len + 1);
		require_efree = 1;
	}

	SwooleG.error = 0;
	ret = cli->recv(cli, buf, buf_len, waitall);
	if (ret < 0)
	{
		SwooleG.error = errno;
		//这里的错误信息没用
		zend_error(E_WARNING, "swoole_client: recv failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, SwooleG.error);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
		zval_ptr_dtor(&errCode);
		RETVAL_FALSE;
	}
	else
	{
		if(ret == 0)
		{
			php_swoole_client_close(&getThis(), cli->sock TSRMLS_CC);
		}
		else
		{
			buf[ret] = 0;
			RETVAL_STRINGL(buf, ret, 1);
		}
	}
	if(require_efree==1) efree(buf);
}

PHP_METHOD(swoole_client, close)
{
	zval **zres, *ztype;
	swClient *cli;
	int ret = 1;

	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	}
	else
	{
		RETURN_FALSE;
	}

	ztype = zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("type")-1, 0 TSRMLS_CC);
	if (ZVAL_IS_NULL(ztype))
	{
		zend_error(E_WARNING, "get swoole_client->type failed.");
		RETURN_FALSE;
	}

	//Connection error, or short tcp connection.
	//No keep connection
	if (!(Z_LVAL_P(ztype) & SW_FLAG_KEEP) && swConnection_error(cli->sock, SwooleG.error) == SW_OK)
	{
		if(cli->async == 1 && SwooleG.main_reactor != NULL)
		{
			ret = php_swoole_client_close(&getThis(), cli->sock TSRMLS_CC);
		}
		else
		{
			ret = cli->close(cli);
		}
	}
	SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_client, on)
{
	char *cb_name;
	int i, cb_name_len;
	zval *zcallback;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
	{
		return;
	}
	zval_add_ref(&getThis());
	for(i=0; i<PHP_CLIENT_CALLBACK_NUM; i++)
	{
		if (strncasecmp(php_sw_callbacks[i]+2, cb_name, cb_name_len) == 0)
		{
			zval_add_ref(&zcallback);
			zend_update_property(swoole_client_class_entry_ptr, getThis(), php_sw_callbacks[i], strlen(php_sw_callbacks[i]), zcallback TSRMLS_CC);
			RETURN_TRUE;
		}
	}
	zend_error(E_WARNING, "swoole_client: event callback[%s] is unknow", cb_name);
	RETURN_FALSE;
}

PHP_FUNCTION(swoole_client_select)
{
	zval *r_array, *w_array, *e_array;
	fd_set rfds, wfds, efds;
	zval *errCode;

	int max_fd = 0;
	int	retval, sets = 0;
	double timeout = 0.5;
	struct timeval timeo;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!a!a!|d", &r_array, &w_array, &e_array, &timeout) == FAILURE)
	{
		return;
	}
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	if (r_array != NULL) sets += php_swoole_client_event_add(r_array, &rfds, &max_fd TSRMLS_CC);
	if (w_array != NULL) sets += php_swoole_client_event_add(w_array, &wfds, &max_fd TSRMLS_CC);
	if (e_array != NULL) sets += php_swoole_client_event_add(e_array, &efds, &max_fd TSRMLS_CC);

	if (!sets)
	{
		zend_error(E_WARNING, "no resource arrays were passed to select");
		RETURN_FALSE;
	}
	if(max_fd >= FD_SETSIZE)
	{
		zend_error(E_WARNING, "select max_fd > FD_SETSIZE[%d]", FD_SETSIZE);
		RETURN_FALSE;
	}
	timeo.tv_sec = (int) timeout;
	timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);

	retval = select(max_fd + 1, &rfds, &wfds, &efds, &timeo);

	if (retval == -1)
	{
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, errno);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
		zend_error(E_WARNING, "swoole_client: unable to select. Error: %s [%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	if (r_array != NULL)
	{
		php_swoole_client_event_loop(r_array, &rfds TSRMLS_CC);
	}
	if (w_array != NULL)
	{
		php_swoole_client_event_loop(w_array, &wfds TSRMLS_CC);
	}
	if (e_array != NULL)
	{
		php_swoole_client_event_loop(e_array, &efds TSRMLS_CC);
	}
	RETURN_LONG(retval);
}

static int php_swoole_client_event_loop(zval *sock_array, fd_set *fds TSRMLS_DC)
{
	zval **element;
	zval *zsock;
	zval **dest_element;
	HashTable *new_hash;
	zend_class_entry *ce;

	char *key;
	int num = 0;
	ulong num_key;
	uint key_len;

	if (Z_TYPE_P(sock_array) != IS_ARRAY)
	{
		return 0;
	}
	ALLOC_HASHTABLE(new_hash);
	zend_hash_init(new_hash, zend_hash_num_elements(Z_ARRVAL_P(sock_array)), NULL, ZVAL_PTR_DTOR, 0);
	for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(sock_array));
	zend_hash_get_current_data(Z_ARRVAL_P(sock_array), (void **) &element) == SUCCESS;
	zend_hash_move_forward(Z_ARRVAL_P(sock_array)))
	{
		ce = Z_OBJCE_P(*element);
		zsock = zend_read_property(ce, *element, SW_STRL("sock")-1, 0 TSRMLS_CC);
		if(ZVAL_IS_NULL(zsock))
		{
			zend_error(E_WARNING, "object is not swoole_client object.");
			continue;
		}
		if ((Z_LVAL(*zsock) < FD_SETSIZE) && FD_ISSET(Z_LVAL(*zsock), fds))
		{
			switch (zend_hash_get_current_key_ex(Z_ARRVAL_P(sock_array), &key, &key_len, &num_key, 0, NULL))
			{
			case HASH_KEY_IS_STRING:
				zend_hash_add(new_hash, key, key_len, (void * )element, sizeof(zval *), (void ** )&dest_element);
				break;
			case HASH_KEY_IS_LONG:
				zend_hash_index_update(new_hash, num_key, (void * )element, sizeof(zval *), (void ** )&dest_element);
				break;
			}
			if (dest_element)
				zval_add_ref(dest_element);
		}
		num++;
	}

	zend_hash_destroy(Z_ARRVAL_P(sock_array));
	efree(Z_ARRVAL_P(sock_array));

	zend_hash_internal_pointer_reset(new_hash);
	Z_ARRVAL_P(sock_array) = new_hash;

	return num ? 1 : 0;
}

static int php_swoole_client_event_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC)
{
	zval **element;
	zval *zsock;
	zend_class_entry *ce;

	int num = 0;
	if (Z_TYPE_P(sock_array) != IS_ARRAY)
	{
		return 0;
	}
	for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(sock_array));
			zend_hash_get_current_data(Z_ARRVAL_P(sock_array), (void **) &element) == SUCCESS;
			zend_hash_move_forward(Z_ARRVAL_P(sock_array)))
	{
		ce = Z_OBJCE_P(*element);
		zsock = zend_read_property(ce, *element, SW_STRL("sock")-1, 0 TSRMLS_CC);
		if(ZVAL_IS_NULL(zsock))
		{
			zend_error(E_WARNING, "object is not swoole_client object.");
			continue;
		}
		if (Z_LVAL(*zsock) < FD_SETSIZE)
		{
			FD_SET(Z_LVAL(*zsock), fds);
		}
		else
		{
			zend_error(E_WARNING, "socket[%ld] > FD_SETSIZE[%d].", Z_LVAL(*zsock), FD_SETSIZE);
			continue;
		}
		if (Z_LVAL(*zsock) > *max_fd)
		{
			*max_fd = Z_LVAL(*zsock);
		}
		num++;
	}
	return num ? 1 : 0;
}
