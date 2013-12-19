#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"

#include "ext/standard/basic_functions.h"

#if PHP_VERSION_ID >= 50301 && (HAVE_SOCKETS || defined(COMPILE_DL_SOCKETS))
#include "ext/sockets/php_sockets.h"
#define SWOOLE_SOCKETS_SUPPORT
#endif

static char php_sw_reactor_ok = 0;
static char php_sw_reactor_wait_onexit = 0;
static char php_sw_in_client = 0;

typedef struct {
	zval *callback;
	zval *socket;
} swoole_reactor_fd;

static int php_swoole_client_event_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC);
static int php_swoole_client_event_loop(zval *sock_array, fd_set *fds TSRMLS_DC);
static int php_swoole_onReactorCallback(swReactor *reactor, swEvent *event);

static int php_swoole_client_onReceive(swReactor *reactor, swEvent *event);
static int php_swoole_client_onConnect(swReactor *reactor, swEvent *event);
static int php_swoole_client_onClose(swReactor *reactor, swEvent *event);
static void php_swoole_check_reactor();
static void php_swoole_try_run_reactor();
static int swoole_convert_to_fd(zval **fd);

static int php_swoole_client_onReceive(swReactor *reactor, swEvent *event)
{
	zval **zobject, *zcallback = NULL;
	zval **args[1];
	zval *retval;

	char *hash_key;
	int hash_key_len;
	hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", event->fd);

	if(zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len+1, &zobject) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_client: Fd[%d] is not a swoole_client object", event->fd);
		return SW_ERR;
	}

	args[0] = zobject;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL("receive")-1, 0 TSRMLS_CC);
	if (zcallback == NULL)
	{
		zend_error(E_WARNING, "SwooleClient: swoole_client object have not receive callback.");
		return SW_ERR;
	}
	if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onReactorCallback handler error");
		return SW_ERR;
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
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

	if(zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len+1, &zobject) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_client->onConnect: Fd=%d is not a swoole_client object", event->fd);
		return SW_ERR;
	}
	args[0] = zobject;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	int error, len = sizeof(error);
	if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
	{
		zend_error(E_WARNING, "swoole_client: getsockopt[sock=%d] fail.Error: %s [%d]", event->fd, strerror(errno), errno);
		return SW_ERR;
	}
	//success
	if(error == 0)
	{
		SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, (SW_FD_USER+1) | SW_EVENT_READ | SW_EVENT_ERROR);
		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL("connect")-1, 0 TSRMLS_CC);
		if (zcallback == NULL)
		{
			zend_error(E_WARNING, "SwooleClient: swoole_client object have not connect callback.");
			return SW_ERR;
		}
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "SwooleServer: onReactorCallback handler error");
			return SW_ERR;
		}
	}
	else
	{
		zend_error(E_WARNING, "SwooleClient: connect to server fail. Error: %s [%d]", strerror(errno), errno);
		SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
		zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL("error")-1, 0 TSRMLS_CC);

		zval *errCode;
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, errno);
		zend_update_property(swoole_client_class_entry_ptr, *zobject, ZEND_STRL("errCode"), errCode TSRMLS_CC);

		if (zcallback == NULL)
		{
			zend_error(E_WARNING, "SwooleClient: swoole_client object have not error callback.");
			return SW_ERR;
		}
		if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			zend_error(E_WARNING, "SwooleServer: onReactorCallback handler error");
			return SW_ERR;
		}
	}
	return SW_OK;
}

static int php_swoole_client_onClose(swReactor *reactor, swEvent *event)
{
	zval **zobject, *zcallback = NULL;
	zval **args[1];
	zval *retval;

	char *hash_key;
	int hash_key_len;
	hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", event->fd);

	if (zend_hash_find(&php_sw_client_callback, hash_key, hash_key_len + 1, &zobject) != SUCCESS)
	{
		zend_error(E_WARNING, "swoole_client: Fd[%d] is not a swoole_client object", event->fd);
		return SW_ERR;
	}

	args[0] = zobject;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	zcallback = zend_read_property(swoole_client_class_entry_ptr, *zobject, SW_STRL("close")-1, 0 TSRMLS_CC);
	if (zcallback == NULL)
	{
		zend_error(E_WARNING, "SwooleClient: swoole_client object have not close callback.");
		return SW_ERR;
	}
	if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleClient: close handle fail.");
		return SW_ERR;
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

static void php_swoole_check_reactor()
{
	if(php_sw_reactor_ok == 0)
	{
		if (SwooleG.main_reactor == NULL)
		{
			SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
			if(SwooleG.main_reactor == NULL)
			{
				zend_error(E_ERROR, "swoole_client: malloc SwooleG.main_reactor fail");
				return;
			}
			int ret;
#ifdef HAVE_EPOLL
			ret = swReactorEpoll_create(SwooleG.main_reactor, SW_MAX_FDS);
#elif defined(HAVE_KQUEUE)
			ret=swReactorKqueue_create(SwooleG.main_reactor, SW_MAX_FDS);
#else
			ret=swReactorSelect_create(SwooleG.main_reactor);
#endif
			if (ret < 0)
			{
				zend_error(E_ERROR, "swoole_client: create SwooleG.main_reactor fail");
				return;
			}
			//client, swoole_event_exit will set swoole_running = 0
			php_sw_in_client = 1;
		}
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER+1) | SW_EVENT_WRITE, php_swoole_client_onConnect);
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER+1) | SW_EVENT_ERROR, php_swoole_client_onClose);
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER+1), php_swoole_client_onReceive);

		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_USER, php_swoole_onReactorCallback);

		php_sw_reactor_ok = 1;
	}
	return;
}

static int php_swoole_onReactorCallback(swReactor *reactor, swEvent *event)
{
	zval *zfd;
	zval *retval;
	zval **args[1];
	swoole_reactor_fd *fd;

	if(zend_hash_find(&php_sw_reactor_callback, (char *)&(event->fd), sizeof(event->fd), &fd) != SUCCESS)
	{
		zend_error(E_WARNING, "SwooleServer: onReactorCallback not found");
		return SW_ERR;
	}

	args[0] = &fd->socket;
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
	if (call_user_function_ex(EG(function_table), NULL, fd->callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		zend_error(E_WARNING, "SwooleServer: onReactorCallback handler error");
		return SW_ERR;
	}
	if (retval != NULL)
	{
		zval_ptr_dtor(&retval);
	}
	return SW_OK;
}


static void php_swoole_try_run_reactor()
{
	//only client side
	if (php_sw_in_client == 1 && php_sw_reactor_wait_onexit == 0)
	{
		TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

		zval *callback, *retval;
		MAKE_STD_ZVAL(callback);

#if PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 4

		php_shutdown_function_entry shutdown_function_entry;

		shutdown_function_entry.arg_count = 1;
	    shutdown_function_entry.arguments = (zval **) safe_emalloc(sizeof(zval *), 1, 0);

		ZVAL_STRING(callback, "swoole_event_wait", 1);
		shutdown_function_entry.arguments[0] = callback;

		TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

		if (!register_user_shutdown_function("swoole_event_wait", sizeof("swoole_event_wait"), &shutdown_function_entry TSRMLS_CC))
		{
			zval_ptr_dtor(&callback);
			efree(shutdown_function_entry.arguments);
			zend_error(E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
		}
#else
		zend_error(E_WARNING, "SwooleClient: PHP%d.%d not support auto run swoole_event_wait. Please append swoole_event_wait at the script end.", PHP_MAJOR_VERSION, PHP_MINOR_VERSION);
#endif
		php_sw_reactor_wait_onexit = 1;
	}
}

static int swoole_convert_to_fd(zval **fd)
{
	php_stream *stream;
	int socket_fd;

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

PHP_FUNCTION(swoole_event_add)
{
	zval *cb;
	zval **fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Zz", &fd, &cb) == FAILURE)
	{
		return;
	}

	int socket_fd = swoole_convert_to_fd(fd);
	if(socket_fd < 0)
	{
		zend_error(E_WARNING, "unknow type.");
		RETURN_FALSE;
	}

	swoole_reactor_fd *event = emalloc(sizeof(swoole_reactor_fd));
	event->socket = *fd;
	event->callback = cb;
	zval_add_ref(&event->callback);

	if(zend_hash_update(&php_sw_reactor_callback, &socket_fd, sizeof(socket_fd), event, sizeof(swoole_reactor_fd), NULL) == FAILURE)
	{
		zend_error(E_WARNING, "swoole_event_add add to hashtable fail");
		RETURN_FALSE;
	}
	php_swoole_check_reactor();
	swSetNonBlock(socket_fd); //must be nonblock
	if(SwooleG.main_reactor->add(SwooleG.main_reactor, socket_fd, SW_FD_USER) < 0)
	{
		zend_error(E_WARNING, "swoole_event_add fail.");
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
	SW_CHECK_RETURN(SwooleG.main_reactor->del(SwooleG.main_reactor, socket_fd));
}

PHP_FUNCTION(swoole_event_exit)
{
	if (php_sw_in_client == 1)
	{
		//stop reactor
		swoole_running = 0;
	}
}

PHP_FUNCTION(swoole_event_wait)
{
	if (php_sw_in_client == 1)
	{
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
	long type, async = 0;
	zval *zres, *errCode, *zsockfd;
	zval *zcallback;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &type, &async) == FAILURE)
	{
		RETURN_FALSE;
	}

	swClient *cli = (swClient*) emalloc(sizeof(swClient));
	if (swClient_create(cli, type, async) < 0)
	{
		zend_error(E_WARNING, "SwooleClient: create fail. Error: %s [%d]", strerror(errno), errno);
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, errno);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errCode TSRMLS_CC);
		RETURN_FALSE;
	}
	MAKE_STD_ZVAL(zres);
	MAKE_STD_ZVAL(zsockfd);
	ZVAL_LONG(zsockfd, cli->sock);

	ZEND_REGISTER_RESOURCE(zres, cli, le_swoole_client);

	zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("sock"), zsockfd TSRMLS_CC);
	zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("_client"), zres TSRMLS_CC);

	zval_ptr_dtor(&zres);
	zval_ptr_dtor(&zsockfd);
	RETURN_TRUE;
}

PHP_METHOD(swoole_client, connect)
{
	int ret;
	long port, udp_connect = 0;
	char *host;
	int host_len;
	double timeout = 0.1; //默认100ms超时

	zval **zres;
	zval *errCode;
	swClient *cli = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|dl", &host, &host_len, &port, &timeout,
			&udp_connect) == FAILURE)
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

	if(cli->async == 0)
	{
		ret = cli->connect(cli, host, port, (float) timeout, udp_connect);
		if (ret < 0)
		{
			zend_error(E_WARNING, "SwooleClient: connect to server[%s:%d] fail. Error: %s [%d]", host, (int)port, strerror(errno), errno);
			MAKE_STD_ZVAL(errCode);
			ZVAL_LONG(errCode, errno);
			zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
			RETURN_FALSE;
		}
		else
		{
			RETURN_TRUE;
		}
	}
	//nonblock async
	else
	{
		char *hash_key;
		int hash_key_len;
		int flag = 0;

		hash_key_len = spprintf(&hash_key, sizeof(int)+1, "%d", cli->sock);
		zval_add_ref(&getThis());

		if (zend_hash_update(&php_sw_client_callback, hash_key, hash_key_len+1, &getThis(), sizeof(zval*), NULL) == FAILURE)
		{
			zend_error(E_WARNING, "swoole_client: add to hashtable fail");
			RETURN_FALSE;
		}

		php_swoole_check_reactor();
		if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
		{
			cli->connect(cli, host, port, (float) timeout, 1);
			flag = (SW_FD_USER+1) | SW_EVENT_WRITE | SW_EVENT_ERROR;
		}
		else
		{
			swEvent ev;
			ev.fd = cli->sock;

			cli->connect(cli, host, port, (float) timeout, udp_connect);
			flag = (SW_FD_USER+1);

			zval *zcallback = NULL;
			zval **args[1];
			zval *retval;

			args[0] = &getThis();
			zcallback = zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("connect")-1, 0 TSRMLS_CC);
			if (zcallback == NULL)
			{
				zend_error(E_WARNING, "SwooleClient: swoole_client object have not connect callback.");
				RETURN_FALSE;
			}
			if (call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
			{
				zend_error(E_WARNING, "SwooleClient: onConnect[udp] handler error");
				RETURN_FALSE;
			}
		}
		ret = SwooleG.main_reactor->add(SwooleG.main_reactor, cli->sock, flag);
		php_swoole_try_run_reactor();
		SW_CHECK_RETURN(ret);
	}
}

PHP_METHOD(swoole_client, send)
{
	char *data;
	int data_len;

	zval **zres;
	swClient *cli;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
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
	SW_CHECK_RETURN(cli->send(cli, data, data_len));
}

PHP_METHOD(swoole_client, recv)
{
	long buf_len = SW_PHP_CLIENT_BUFFER_SIZE, waitall = 0;
	char require_efree = 0;
	char buf_array[SW_PHP_CLIENT_BUFFER_SIZE];
	char *buf;
	zval **zres;
	zval *errCode;
	zval *zretval;

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

	if ((ret = cli->recv(cli, buf, buf_len, waitall)) <= 0)
	{
		//这里的错误信息没用
		zend_error(E_WARNING, "swoole_client: recv fail.Error: %s [%d]", strerror(errno), errno);
		MAKE_STD_ZVAL(errCode);
		ZVAL_LONG(errCode, errno);
		zend_update_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errCode TSRMLS_CC);
		RETVAL_FALSE;
	}
	else
	{
//		swWarn("data=%s|ret=%d", buf, ret);
		buf[ret] = 0;
		RETVAL_STRINGL(buf, ret, 1);
	}
	if(require_efree==1) efree(buf);
}

PHP_METHOD(swoole_client, close)
{
	zval **zres;
	zval **zsock;
	swClient *cli;
	int ret;

	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **) &zres) == SUCCESS)
	{
		ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);
	}
	else
	{
		RETURN_FALSE;
	}
	if(cli->async == 1 && SwooleG.main_reactor != NULL)
	{
		ret = SwooleG.main_reactor->del(SwooleG.main_reactor, cli->sock);
		cli->sock = 0;
	}
	else
	{
		ret = cli->close(cli);
	}
	SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_client, on)
{
	zval **zres;
	swClient *cli;

	char *cb_name;
	int i, ret, cb_name_len;
	zval *zcallback;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
	{
		return;
	}
	if (zend_hash_find(Z_OBJPROP_P(getThis()), SW_STRL("_client"), (void **) &zres) != SUCCESS)
	{
		RETURN_FALSE;
	}
	ZEND_FETCH_RESOURCE(cli, swClient*, zres, -1, SW_RES_CLIENT_NAME, le_swoole_client);

	//必须与define顺序一致
	char *callbacks[PHP_CLIENT_CALLBACK_NUM] = {
		"connect",
		"receive",
		"close",
		"error",
	};
	zval_add_ref(&getThis());
	for(i=0; i<PHP_CLIENT_CALLBACK_NUM; i++)
	{
		if(strncasecmp(callbacks[i], cb_name, cb_name_len) == 0)
		{
			//调用on接口自动修改为异步模式
			if(cli->async == 0)
			{
				cli->async = 1;
			}
			zval_add_ref(&zcallback);
			zend_update_property(swoole_client_class_entry_ptr, getThis(), cb_name, cb_name_len, zcallback TSRMLS_CC);
			RETURN_TRUE;
		}
	}
	zend_error(E_WARNING, "swoole_client: callback[%s] is unknow", cb_name);
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
		zend_error(E_WARNING, "SwooleClient: unable to select. Error: %s [%d]", strerror(errno), errno);
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
	swClient *cli;
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
		if(!zsock)
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
	swClient *cli;
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
		if(!zsock)
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
