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

#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"

#include "ext/standard/basic_functions.h"

#define php_sw_client_onConnect     "onConnect"
#define php_sw_client_onReceive     "onReceive"
#define php_sw_client_onClose       "onClose"
#define php_sw_client_onError       "onError"

static PHP_METHOD(swoole_client, __construct);
static PHP_METHOD(swoole_client, __destruct);
static PHP_METHOD(swoole_client, set);
static PHP_METHOD(swoole_client, connect);
static PHP_METHOD(swoole_client, recv);
static PHP_METHOD(swoole_client, send);
static PHP_METHOD(swoole_client, sendfile);
static PHP_METHOD(swoole_client, sendto);
static PHP_METHOD(swoole_client, isConnected);
static PHP_METHOD(swoole_client, getsockname);
static PHP_METHOD(swoole_client, getpeername);
static PHP_METHOD(swoole_client, close);
static PHP_METHOD(swoole_client, on);

static int client_event_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC);
static int client_event_loop(zval *sock_array, fd_set *fds TSRMLS_DC);
static int client_close(zval *zobject, int fd TSRMLS_DC);

static int client_onRead(swReactor *reactor, swEvent *event);
static int client_onPackage(zval *zobject, swClient *cli TSRMLS_DC);
static int client_onWrite(swReactor *reactor, swEvent *event);
static int client_onError(swReactor *reactor, swEvent *event);

static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC);
static int client_error_callback(zval *zobject, swEvent *event, int error TSRMLS_DC);
static swClient* client_create_socket(zval *object, char *host, int host_len, int port);

static char *php_sw_callbacks[PHP_CLIENT_CALLBACK_NUM] =
{
	php_sw_client_onConnect,
	php_sw_client_onReceive,
	php_sw_client_onClose,
	php_sw_client_onError,
};

static const zend_function_entry swoole_client_methods[] =
{
    PHP_ME(swoole_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, recv, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, send, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendfile, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendto, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getsockname, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getpeername, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, on, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

HashTable php_sw_long_connections;

zend_class_entry swoole_client_ce;
zend_class_entry *swoole_client_class_entry_ptr;

void swoole_client_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", swoole_client_methods);
    swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);

    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_hash_init(&php_sw_long_connections, 16, NULL, ZVAL_PTR_DTOR, 1);
}

/**
 * @zobject: swoole_client object
 */
static int client_close(zval *zobject, int fd TSRMLS_DC)
{
	zval *zcallback = NULL;
	zval *retval = NULL;
	zval **args[1];

    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        return SW_ERR;
    }

	//long tcp connection, clear from php_sw_long_connections
	zval *ztype = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL("type")-1, 0 TSRMLS_CC);
	if (ztype == NULL || ZVAL_IS_NULL(ztype))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "get swoole_client->type failed.");
	}
	else if (Z_LVAL_P(ztype) & SW_FLAG_KEEP)
	{
		if (sw_zend_hash_del(&php_sw_long_connections, cli->server_str, cli->server_strlen) == SUCCESS)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "delete from hashtable failed.");
		}
        sw_free(cli->server_str);
		ZVAL_LONG(ztype, 0);
	}
	else
	{
	    sw_free(cli->server_str);
	}

    if (cli->buffer && (cli->open_eof_split || cli->open_length_check))
    {
        swString_free(cli->buffer);
        cli->buffer = NULL;
    }

	//async connection
	if (cli->async)
	{
		//remove from reactor
		if (SwooleG.main_reactor)
		{
			SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
		}

		zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL(php_sw_client_onClose)-1, 0 TSRMLS_CC);
		if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client->close[3]: no close callback.");
			return SW_ERR;
		}

		args[0] = &zobject;

		if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client->close[4]: onClose handler error");
			return SW_ERR;
		}

		if (SwooleG.main_reactor->event_num == 0 && SwooleWG.in_client == 1)
		{
			SwooleG.running = 0;
		}

        cli->close(cli);
        //free the callback return value
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
	}
	else
	{
		cli->close(cli);
	}
	return SW_OK;
}

static int client_onRead_check_eof(swReactor *reactor, swEvent *event)
{
    int n;
    zval *zobject;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zobject = event->socket->object;
    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        return SW_ERR;
    }

    int recv_again = SW_FALSE;
    int eof_pos = -1;
    int buf_size;

    char stack_buf[SW_PHP_CLIENT_BUFFER_SIZE];
    swConnection *conn = cli->socket;
    swProtocol *protocol = &cli->protocol;

    if (cli->buffer == NULL)
    {
        cli->buffer = swString_new(SW_BUFFER_SIZE);
        //alloc memory failed.
        if (!cli->buffer)
        {
            return SW_ERR;
        }
    }
    swString *buffer = cli->buffer;

    recv_data:
    buf_size = buffer->size - buffer->length;
    char *buf_ptr = buffer->str + buffer->length;

    if (buf_size > SW_PHP_CLIENT_BUFFER_SIZE)
    {
        buf_size = SW_PHP_CLIENT_BUFFER_SIZE;
    }

#ifdef SW_USE_EPOLLET
    n = swRead(event->fd, trunk->data, SW_PHP_CLIENT_BUFFER_SIZE);
#else
    //level trigger
    n = swConnection_recv(conn, buf_ptr, buf_size, 0);
#endif

    swTrace("ReactorThread: recv[len=%d]", n);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection[%d@%d] failed.", event->fd, reactor->id);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        goto close_fd;
    }
    else
    {
        buffer->length += n;

        if (buffer->length < protocol->package_eof_len)
        {
            return SW_OK;
        }

        //find EOF
        find_eof:
        eof_pos = swoole_strnpos(buffer->str, buffer->length, protocol->package_eof, protocol->package_eof_len);

        if (eof_pos >= 0)
        {
            int offset = eof_pos + protocol->package_eof_len;

            if (buffer->length > offset)
            {
                int remaining_length = buffer->length - offset;
                //swWarn("eof_pos=%d, total_length=%d, remaining_length=%d", eof_pos, buffer->length, remaining_length);
                memcpy(stack_buf, buffer->str + offset, remaining_length);
                buffer->length = offset;

                client_onPackage(zobject, cli TSRMLS_CC);

                memcpy(buffer->str, stack_buf, remaining_length);
                buffer->length = remaining_length;

                goto find_eof;
            }
            else
            {
                client_onPackage(zobject, cli TSRMLS_CC);
                buffer->length = 0;
                return SW_OK;
            }
        }

        //over max length, will discard
        if (buffer->length == protocol->package_max_length)
        {
            swWarn("Package is too big. package_length=%d", (int )buffer->length);
            goto close_fd;
        }
        //buffer is full, may have not read data
        if (buf_size == n)
        {
            recv_again = SW_TRUE;
            if (buffer->size < protocol->package_max_length)
            {
                uint32_t extend_size = buffer->size * 2;
                if (extend_size > protocol->package_max_length)
                {
                    extend_size = protocol->package_max_length;
                }
                if (swString_extend(buffer, extend_size) < 0)
                {
                    return SW_ERR;
                }
            }
        }
        //no eof
        if (recv_again)
        {
            goto recv_data;
        }
    }
    close_fd:
    return client_close(zobject, event->fd TSRMLS_CC);
}

static int client_onRead_check_length(swReactor *reactor, swEvent *event)
{
    int n;
    zval *zobject;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zobject = event->socket->object;
    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        return SW_ERR;
    }

    swConnection *conn = cli->socket;

    if (cli->buffer == NULL)
    {
        cli->buffer = swString_new(SW_BUFFER_SIZE);
        //alloc memory failed.
        if (!cli->buffer)
        {
            return SW_ERR;
        }
    }

    swString *buffer = cli->buffer;
    uint32_t buf_size;
    if (buffer->offset)
    {
        buf_size = buffer->offset - buffer->length;
    }
    else
    {
        buf_size = buffer->size - buffer->length;
    }
    char *buf_ptr = buffer->str + buffer->length;

    n = swConnection_recv(conn, buf_ptr, buf_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("recv from connection[%d@%d] failed.", event->fd, reactor->id);
            return SW_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        goto close_fd;
    }
    else
    {
        buffer->length += n;
        while (1)
        {
            if (cli->wait_data)
            {
                if (buffer->length == buffer->offset)
                {
                    client_onPackage(zobject, cli TSRMLS_CC);
                    swString_clear(buffer);
                    cli->wait_data = 0;
                }
                return SW_OK;
            }
            else
            {
                int package_length = swProtocol_get_package_length(&cli->protocol, cli->socket, buffer->str, buffer->length);
                if (package_length == 0)
                {
                    return SW_OK;
                }
                else if (package_length < 0)
                {
                    goto close_fd;
                }
                else
                {
                    if (package_length > buffer->size)
                    {
                        swString_extend(buffer, package_length);
                    }
                    buffer->offset = package_length;
                    cli->wait_data = 1;
                }
            }
        }
    }
    close_fd:
    return client_close(zobject, event->fd TSRMLS_CC);
}

static int client_onRead(swReactor *reactor, swEvent *event)
{
	int n;
	zval *zobject, *zcallback = NULL;
	zval **args[2];
	zval *retval = NULL;
	char *buf = NULL;
	long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

	zobject = event->socket->object;
    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        return SW_ERR;
    }

    if (cli->open_eof_split)
    {
        return client_onRead_check_eof(reactor, event);
    }
    else if (cli->open_length_check)
    {
        return client_onRead_check_length(reactor, event);
    }
    //packet mode
    else if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = 0;
        n = recv(event->fd, &len_tmp, 4, 0);
        if (n <= 0)
        {
            return client_close(zobject, event->fd TSRMLS_CC);
        }
        else
        {
            buf_len = ntohl(len_tmp);
        }
    }

    buf = emalloc(buf_len + 1);

#ifdef SW_CLIENT_RECV_AGAIN
    recv_again:
#endif

    n = recv(event->fd, buf, buf_len, 0);
	if (n < 0)
	{
		switch (swConnection_error(errno))
		{
		case SW_ERROR:
			swSysError("Read from socket[%d] failed.", event->fd);
			goto free_buf;
		case SW_CLOSE:
			goto close_fd;
        case SW_WAIT:
            if (cli->packet_mode == 1)
            {
                goto recv_again;
            }
            else
            {
                goto free_buf;
            }
		default:
			swTrace("default");
		    goto free_buf;
		}
	}
	else if (n == 0)
	{
		close_fd:
		if (buf)
        {
            efree(buf);
        }
		return client_close(zobject, event->fd TSRMLS_CC);
	}
	else
	{
		zval *zdata;
		SW_MAKE_STD_ZVAL(zdata,0);
	    buf[n] = 0;
		SW_ZVAL_STRINGL(zdata, buf, n, 0);

		args[0] = &zobject;
		args[1] = &zdata;

		zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL(php_sw_client_onReceive)-1, 0 TSRMLS_CC);
		if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client object have not receive callback.");
			goto free_zdata;
		}

		if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "onReactorCallback handler error");
			goto free_zdata;
		}
		if (retval != NULL)
		{
			sw_zval_ptr_dtor(&retval);
		}

#ifdef SW_CLIENT_RECV_AGAIN
        if (n == SW_CLIENT_BUFFER_SIZE)
        {
            goto recv_again;
        }
#endif
        free_zdata:
        sw_zval_ptr_dtor(&zdata);
        return SW_OK;
	}

	free_buf:
	efree(buf);
	return SW_OK;
}

static int client_onPackage(zval *zobject, swClient *cli TSRMLS_DC)
{
    zval *zcallback = NULL;
    zval **args[2];
    zval *retval;

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata,0);
    SW_ZVAL_STRINGL(zdata, cli->buffer->str, cli->buffer->length, 1);

    args[0] = &zobject;
    args[1] = &zdata;

    zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL(php_sw_client_onReceive)-1, 0 TSRMLS_CC);
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client object have not receive callback.");
        goto free_zdata;
    }

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onReactorCallback handler error");
        goto free_zdata;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
    return SW_OK;
}

static int client_onError(swReactor *reactor, swEvent *event)
{
	zval *zobject = event->socket->object;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

	int error;
	socklen_t len = sizeof(error);

	if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client->onError[2]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
	}
	client_error_callback(zobject, event, error TSRMLS_CC);
	return SW_OK;
}

static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    HashTable *vht;
    zval *v;

    vht = Z_ARRVAL_P(zset);

   //buffer: check eof
   if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_split"), (void **)&v) == SUCCESS ||
           sw_zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **)&v) == SUCCESS )
   {
       convert_to_boolean(v);
       cli->open_eof_split = (uint8_t) Z_BVAL_P(v);
   }
   //package eof
   if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &v) == SUCCESS)
   {
       convert_to_string(v);
       cli->protocol.package_eof_len = Z_STRLEN_P(v);
       if (cli->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
       {
           php_error_docref(NULL TSRMLS_CC, E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
           return;
       }
       bzero(cli->protocol.package_eof, SW_DATA_EOF_MAXLEN);
       memcpy(cli->protocol.package_eof, Z_STRVAL_P(v), Z_STRLEN_P(v));
   }
   //open length check
   if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **)&v) == SUCCESS)
   {
       convert_to_long(v);
       cli->open_length_check = (uint8_t) Z_LVAL_P(v);
   }
   //package length size
   if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **)&v) == SUCCESS)
   {
       convert_to_string(v);
       cli->protocol.package_length_type = Z_STRVAL_P(v)[0];
       cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

       if (cli->protocol.package_length_size == 0)
       {
           php_error_docref(NULL TSRMLS_CC, E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
           return;
       }
   }
   //package length offset
   if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **)&v) == SUCCESS)
   {
       convert_to_long(v);
       cli->protocol.package_length_offset = (int)Z_LVAL_P(v);
   }
   //package body start
   if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &v) == SUCCESS
           || sw_zend_hash_find(vht, ZEND_STRS("package_body_start"), (void **) &v) == SUCCESS)
   {
       convert_to_long(v);
       cli->protocol.package_body_offset = (int) Z_LVAL_P(v);
   }
   /**
    * package max length
    */
   if (sw_zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &v) == SUCCESS)
   {
       convert_to_long(v);
       cli->protocol.package_max_length = (int) Z_LVAL_P(v);
   }
   else
   {
       cli->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
   }
}

static int client_onWrite(swReactor *reactor, swEvent *event)
{
	zval *zobject = event->socket->object;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        return SW_ERR;
    }

    if (cli->socket->active)
    {
        return swReactor_onWrite(SwooleG.main_reactor, event);
    }
	else
	{
		zval *zcallback = NULL;
		zval **args[1];
		zval *retval = NULL;
		int error;
		socklen_t len = sizeof(error);

		args[0] = &zobject;

		if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
			return SW_ERR;
		}
		//success
		if (error == 0)
        {
            SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, (SW_FD_USER + 1) | SW_EVENT_READ);

			//connected
			cli->socket->active = 1;

			zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL(php_sw_client_onConnect)-1, 0 TSRMLS_CC);
			if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: swoole_client object have not connect callback.");
				return SW_ERR;
			}
			if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: onConnect handler error");
				return SW_ERR;
			}
			if (retval)
			{
				sw_zval_ptr_dtor(&retval);
			}
		}
		else
		{
			client_error_callback(zobject, event, error TSRMLS_CC);
			event->socket->removed = 1;
		}
	}

	return SW_OK;
}

static int client_error_callback(zval *zobject, swEvent *event, int error TSRMLS_DC)
{
	zval *zcallback;
	zval *retval = NULL;
	zval **args[1];

	if (error != 0)
	{
	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: connect to server failed. Error: %s [%d]", strerror(error), error);
	}

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);
    zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, zobject, SW_STRL(php_sw_client_onError)-1, 0 TSRMLS_CC);

    zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), error TSRMLS_CC);

	args[0] = &zobject;

	if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: swoole_client object have not error callback.");
		return SW_ERR;
	}

	if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: onError handler error");
		return SW_ERR;
	}

	if (retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
	return SW_OK;
}

void php_swoole_at_shutdown(char *function)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *callback;
    SW_MAKE_STD_ZVAL(callback,0);
    SW_ZVAL_STRING(callback, "swoole_event_wait", 1);

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4
    php_shutdown_function_entry shutdown_function_entry;

    shutdown_function_entry.arg_count = 1;
    shutdown_function_entry.arguments = (zval **) safe_emalloc(sizeof(zval *), 1, 0);


    shutdown_function_entry.arguments[0] = callback;

    if (!register_user_shutdown_function("swoole_event_wait", sizeof("swoole_event_wait"), &shutdown_function_entry TSRMLS_CC))
    {
        efree(shutdown_function_entry.arguments);
        sw_zval_ptr_dtor(&callback);
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
    }
#else
    zval *register_shutdown_function;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(register_shutdown_function,1);
    SW_ZVAL_STRING(register_shutdown_function, "register_shutdown_function", 1);
    zval **args[1] = {&callback};

    if (sw_call_user_function_ex(EG(function_table), NULL, register_shutdown_function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
        return;
    }
#endif
}

void php_swoole_check_reactor()
{
	if (SwooleWG.reactor_init == 0)
	{

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

        if (!SWOOLE_G(cli))
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "async-io must use in cli environment.");
            return;
        }

        if (swIsTaskWorker())
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "cannot use async-io in task process.");
            return;
        }

		if (SwooleG.main_reactor == NULL)
		{
			SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
            if (SwooleG.main_reactor == NULL)
            {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "malloc failed.");
                return;
            }
			if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
			{
				php_error_docref(NULL TSRMLS_CC, E_ERROR, "create reactor failed.");
				return;
			}
			//client, swoole_event_exit will set swoole_running = 0
			SwooleWG.in_client = 1;
			SwooleWG.reactor_wait_onexit = 1;
            SwooleWG.reactor_ready = 0;
            //only client side
            php_swoole_at_shutdown("swoole_event_wait");
		}

        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_READ, client_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_WRITE, client_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_ERROR, client_onError);

        php_swoole_event_init();

		SwooleWG.reactor_init = 1;
	}
	return;
}

static swClient* client_create_socket(zval *object, char *host, int host_len, int port)
{
    zval *ztype;
    int async = 0;
    int packet_mode = 0;
    char conn_key[SW_LONG_CONNECTION_KEY_LEN];
    int conn_key_len = 0;
    uint64_t tmp_buf;
    int ret;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    ztype = sw_zend_read_property(swoole_client_class_entry_ptr, object, SW_STRL("type")-1, 0 TSRMLS_CC);

    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "get swoole_client->type failed.");
        return NULL;
    }

    long type_tmp = Z_LVAL_P(ztype);
    packet_mode = type_tmp & SW_MODE_PACKET;
    packet_mode >>= 4;
    long type = type_tmp & (~SW_MODE_PACKET);

    //debug
    //swTrace("type:%d,type_tmp:%d\r\n",type,type_tmp);

    //new flag, swoole-1.6.12+
    if (type & SW_FLAG_ASYNC)
    {
        async = 1;
    }

    swClient *cli;

	bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);
	zval *connection_id = sw_zend_read_property(swoole_client_class_entry_ptr, object, ZEND_STRL("id"), 1 TSRMLS_CC);

    if (connection_id == NULL || ZVAL_IS_NULL(connection_id))
    {
        conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s:%d", host, port) + 1;
    }
    else
    {
        conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s", Z_STRVAL_P(connection_id)) + 1;
    }

    //keep the tcp connection
    if (type & SW_FLAG_KEEP)
    {
        swClient *find;

        if (sw_zend_hash_find(&php_sw_long_connections, conn_key, conn_key_len, (void **) &find) == FAILURE)
        {
            cli = (swClient*) pemalloc(sizeof(swClient), 1);
            if (sw_zend_hash_update(&php_sw_long_connections, conn_key, conn_key_len, (void*)cli, sizeof(cli), NULL) == FAILURE)
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client_create_socket add to hashtable failed.");
            }
            goto create_socket;
        }
        else
        {
            cli = find;
            //try recv, check connection status
            ret = recv(cli->socket->fd, &tmp_buf, sizeof(tmp_buf), MSG_DONTWAIT | MSG_PEEK);
            if (ret == 0 || (ret < 0 && swConnection_error(errno) == SW_CLOSE))
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
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "create failed. Error: %s [%d]", strerror(errno), errno);
            zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("errCode"), errno TSRMLS_CC);
            return NULL;
        }
        //don't forget free it
        cli->server_str = strdup(conn_key);
        cli->server_strlen = conn_key_len;
    }

    swoole_set_object(object, cli);
    zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    if (type & SW_FLAG_KEEP)
    {
        cli->keep = 1;
    }
    if (packet_mode == 1)
    {
        cli->packet_mode = 1;
    }
	return cli;
}

static PHP_METHOD(swoole_client, __construct)
{
    long async = 0;
    zval *ztype;
    char *id = NULL;
    zend_size_t len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|ls", &ztype, &async, &id, &len) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require socket type param.");
        RETURN_FALSE;
    }

    if (async == 1)
    {
        Z_LVAL_P(ztype) = Z_LVAL_P(ztype) | SW_FLAG_ASYNC;
    }

    if ((Z_LVAL_P(ztype) & SW_FLAG_ASYNC))
    {
        php_swoole_check_reactor();
    }

    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), ztype TSRMLS_CC);
    if (id)
    {
        zend_update_property_stringl(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("id"), id, len TSRMLS_CC);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, __destruct)
{
    swClient *cli = swoole_get_object(getThis());
    if (cli && cli->keep == 0)
    {
        if (cli->socket->fd != 0)
        {
            cli->close(cli);
        }
        efree(cli);
    }
}

static PHP_METHOD(swoole_client, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, connect)
{
	int ret, i;
	long port = 0, sock_flag = 0;
	char *host = NULL;
	zend_size_t host_len;
	double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

	zval *callback = NULL;
	swClient *cli = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ldl", &host, &host_len, &port, &timeout,
			&sock_flag) == FAILURE)
	{
		return;
	}

	if (host_len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "The host is empty.");
        RETURN_FALSE;
    }

	cli = client_create_socket(getThis(), host, host_len, port);

	if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
	{
        if (port <= 0 || port > SW_CLIENT_MAX_PORT)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "The port is invalid.");
            RETURN_FALSE;
        }
        if (cli->async == 1)
        {
            //for tcp: nonblock
            //for udp: have udp connect
            sock_flag = 1;
        }
	}

    if (cli->keep == 1 && cli->socket->active == 1)
    {
        RETURN_TRUE;
    }
    else if (cli->socket->active == 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client is already connected.");
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        client_check_setting(cli, zset TSRMLS_CC);
    }

	ret = cli->connect(cli, host, port, timeout, sock_flag);

	//nonblock async
	if (cli->async)
	{
		if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
		{
			//check callback function
            for (i = 0; i < PHP_CLIENT_CALLBACK_NUM; i++)
			{
				callback = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), php_sw_callbacks[i], strlen(php_sw_callbacks[i]), 1 TSRMLS_CC);
				if (callback == NULL || ZVAL_IS_NULL(callback))
				{
					php_error_docref(NULL TSRMLS_CC, E_ERROR, "no %s callback.", php_sw_callbacks[i]);
					RETURN_FALSE;
				}
			}
		}
		else
		{
			callback = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL(php_sw_client_onReceive)-1, 1 TSRMLS_CC);
			if (callback == NULL || ZVAL_IS_NULL(callback))
			{
				php_error_docref(NULL TSRMLS_CC, E_ERROR, "no receive callback.");
				RETURN_FALSE;
			}
		}

        int reactor_flag = 0;

        cli->socket->object = getThis();
        cli->reactor_fdtype = SW_FD_USER + 1;
        zval *obj = getThis();
        sw_zval_add_ref(&obj);

		if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
		{
			reactor_flag = cli->reactor_fdtype | SW_EVENT_WRITE;
		}
		else
		{
			reactor_flag = cli->reactor_fdtype;

			zval *zcallback = NULL;
			zval **args[1];
			zval *retval = NULL;
                        args[0] = &obj;
                        
			zcallback = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL(php_sw_client_onConnect)-1, 0 TSRMLS_CC);
            if (callback == NULL || ZVAL_IS_NULL(callback))
			{
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client object have not connect callback.");
				RETURN_FALSE;
			}
			if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
            {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "onConnect[udp] handler error");
                RETURN_FALSE;
            }
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
        }
        ret = SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, reactor_flag);
        SW_CHECK_RETURN(ret);
	}
	else if (ret < 0)
	{
	    swoole_php_error(E_WARNING, "connect to server[%s:%d] failed. Error: %s [%d]", host, (int)port, strerror(errno), errno);
		zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errno TSRMLS_CC);
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

static PHP_METHOD(swoole_client, send)
{
	char *data;
	zend_size_t data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
	{
		return;
	}

	if (data_len <= 0)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
		RETURN_FALSE;
	}

	swClient *cli = swoole_get_object(getThis());
	if (!cli)
	{
	    swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
		RETURN_FALSE;
	}

	if (cli->socket->active == 0)
	{
	    swoole_php_error(E_WARNING, "server is not connected.");
		RETURN_FALSE;
	}

	//clear errno
	SwooleG.error = 0;
	int ret;

    if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = htonl(data_len);
        ret = cli->send(cli, (char *) &len_tmp, 4);
        if (ret < 0)
        {
            goto send_error;
        }
    }

	ret = cli->send(cli, data, data_len);
	if (ret < 0)
    {
	    send_error:
        SwooleG.error = errno;
        swoole_php_error(E_WARNING, "send() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
	else
	{
		RETVAL_TRUE;
	}
}

static PHP_METHOD(swoole_client, sendto)
{
    char* ip;
    char* ip_len;
    zend_size_t port;

    char *data;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &ip, &ip_len, &port, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        swoole_php_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }

    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
    }

    int ret;
    if (cli->type == SW_SOCK_UDP)
    {
        ret = swSocket_udp_sendto(cli->socket->fd, ip, port, data, len);
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        ret = swSocket_udp_sendto6(cli->socket->fd, ip, port, data, len);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, sendfile)
{
    char *file;
    zend_size_t file_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &file, &file_len) == FAILURE)
    {
        return;
    }
    if (file_len <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "file is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }

    if (!(cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UNIX_STREAM))
    {
        swoole_php_error(E_WARNING, "dgram socket cannot use sendfile.");
        RETURN_FALSE;
    }
    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "Server is not connected.");
        RETURN_FALSE;
    }
    //clear errno
    SwooleG.error = 0;
    int ret = cli->sendfile(cli, file);
    if (ret < 0)
    {
        SwooleG.error = errno;
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "sendfile() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client, recv)
{
    long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    zend_bool waitall = 0;
    int ret;
    char *buf = NULL;
    char stack_buf[SW_BUFFER_SIZE_BIG];

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|lb", &buf_len, &waitall) == FAILURE)
	{
		return;
	}

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }

    if (!waitall && buf_len > SW_PHP_CLIENT_BUFFER_SIZE)
    {
        buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    }

	if (cli->socket->active == 0)
	{
		swoole_php_error(E_WARNING, "server is not connected.");
		RETURN_FALSE;
	}

	swProtocol *protocol = &cli->protocol;

	if (cli->open_eof_split)
	{
        if (cli->buffer == NULL)
        {
            cli->buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }

        swString *buffer = cli->buffer;
        int eof = -1;

	    while (1)
        {
            buf = buffer->str + buffer->length;
            buf_len = buffer->size - buffer->length;

            if (buf_len > SW_BUFFER_SIZE_BIG)
            {
                buf_len = SW_BUFFER_SIZE_BIG;
            }

            ret = cli->recv(cli, buf, buf_len, 0);
            if (ret < 0)
            {
                swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(errno), errno);
                buffer->length = 0;
                RETURN_FALSE;
            }
            else if (ret == 0)
            {
                buffer->length = 0;
                RETURN_EMPTY_STRING();
            }

            buffer->length += ret;

            if (buffer->length < protocol->package_eof_len)
            {
                continue;
            }

            eof = swoole_strnpos(buffer->str, buffer->length, protocol->package_eof, protocol->package_eof_len);
            if (eof >= 0)
            {
                eof += protocol->package_eof_len;
                SW_RETVAL_STRINGL(buffer->str, eof, 1);

                if (buffer->length > eof)
                {
                    buffer->length -= eof;
                    memcpy(stack_buf, buffer->str + eof, buffer->length);
                    memcpy(buffer->str, stack_buf, buffer->length);
                }
                else
                {
                    buffer->length = 0;
                }
                return;
            }
            else
            {
                if (buffer->length == protocol->package_max_length)
                {
                    swoole_php_error(E_WARNING, "no package eof");
                    buffer->length = 0;
                    RETURN_FALSE;
                }
                else if (buffer->length == buffer->size)
                {
                    if (buffer->size < protocol->package_max_length)
                    {
                        int new_size = buffer->size * 2;
                        if (new_size > protocol->package_max_length)
                        {
                            new_size = protocol->package_max_length;
                        }
                        if (swString_extend(buffer, new_size) < 0)
                        {
                            buffer->length = 0;
                            RETURN_FALSE;
                        }
                    }
                }
            }
        }
	    buffer->length = 0;
	    RETURN_FALSE;
	}
	else if (cli->open_length_check)
	{
        uint32_t header_len = protocol->package_length_offset + protocol->package_length_size;
        ret = cli->recv(cli, stack_buf, header_len, 1);
        if (ret <= 0)
        {
            goto check_return;
        }

        buf_len = swProtocol_get_package_length(protocol, cli->socket, stack_buf, ret);
        if (buf_len < 0)
        {
            RETURN_FALSE;
        }

        buf = emalloc(buf_len + 1);
        memcpy(buf, stack_buf, header_len);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf + header_len, buf_len - header_len, 1);
        if (ret > 0)
        {
            ret += header_len;
        }
	}
	else if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = 0;
        ret = cli->recv(cli, (char*) &len_tmp, 4, 1);
        if (ret < 0)
        {
            swoole_php_error(E_WARNING, "recv() header failed. Error: %s [%d]", strerror(errno), errno);
            RETURN_FALSE;
        }
        else
        {
            len_tmp = ntohl(len_tmp);
            buf_len = len_tmp;
        }

        buf = emalloc(buf_len + 1);
        SwooleG.error = 0;
        //PACKET mode, must use waitall.
        ret = cli->recv(cli, buf, buf_len, 1);
    }
    else
    {
        buf = emalloc(buf_len + 1);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf, buf_len, waitall);
    }

	check_return:

	if (ret < 0)
	{
		SwooleG.error = errno;
		swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
		zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
		if (buf)
		{
	        efree(buf);
		}
		RETURN_FALSE;
	}
    else
    {
        if (ret == 0)
        {
            RETURN_EMPTY_STRING();
        }
        else
        {
            buf[ret] = 0;
            SW_RETURN_STRINGL(buf, ret, 0);
        }
    }
}

static PHP_METHOD(swoole_client, isConnected)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->socket->active);
}

static PHP_METHOD(swoole_client, getsockname)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }
    if (!cli->socket->active)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UNIX_STREAM || cli->type == SW_SOCK_UNIX_DGRAM)
    {
        swoole_php_fatal_error(E_WARNING, "getsockname() only support AF_INET family socket.");
        RETURN_FALSE;
    }

    cli->socket->info.len = sizeof(cli->socket->info.addr);
    if (getsockname(cli->socket->fd, (struct sockaddr*) &cli->socket->info.addr, &cli->socket->info.len) < 0)
    {
        swoole_php_sys_error(E_WARNING, "getsockname() failed.");
        RETURN_FALSE;
    }

    array_init(return_value);
    if (cli->type == SW_SOCK_UDP6 || cli->type == SW_SOCK_TCP6)
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &cli->socket->info.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            sw_add_assoc_string(return_value, "host", tmp, 1);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed.");
        }
    }
    else
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v4.sin_port));
        sw_add_assoc_string(return_value, "host", inet_ntoa(cli->socket->info.addr.inet_v4.sin_addr), 1);
    }
}

static PHP_METHOD(swoole_client, getpeername)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }

    if (!cli->socket->active)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UDP)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v4.sin_port));
        sw_add_assoc_string(return_value, "host", inet_ntoa(cli->remote_addr.addr.inet_v4.sin_addr), 1);
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &cli->remote_addr.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            sw_add_assoc_string(return_value, "host", tmp, 1);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed.");
        }
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client, close)
{
	zval *ztype;
	int ret = 1;

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
        RETURN_FALSE;
    }

	if (!cli->socket->active)
	{
	    swoole_php_error(E_WARNING, "not connected to the server");
	    RETURN_FALSE;
	}

	ztype = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("type")-1, 0 TSRMLS_CC);
	if (ztype == NULL || ZVAL_IS_NULL(ztype))
	{
	    swoole_php_error(E_WARNING, "get swoole_client->type failed.");
		RETURN_FALSE;
	}

	//Connection error, or short tcp connection.
	//No keep connection
	if (!(Z_LVAL_P(ztype) & SW_FLAG_KEEP) || swConnection_error(SwooleG.error) == SW_CLOSE)
	{
		if (cli->async == 1 && SwooleG.main_reactor != NULL)
		{
			ret = client_close(getThis(), cli->socket->fd TSRMLS_CC);
		}
		else if (cli->socket->fd != 0)
		{
			ret = cli->close(cli);
		}
	}
	SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, on)
{
	char *cb_name;
	int i, cb_name_len;
	zval *zcallback;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
	{
		return;
	}

	sw_zval_add_ref(&zcallback);

    for (i = 0; i < PHP_CLIENT_CALLBACK_NUM; i++)
    {
        if (strncasecmp(php_sw_callbacks[i] + 2, cb_name, cb_name_len) == 0)
        {
            zend_update_property(swoole_client_class_entry_ptr, getThis(), php_sw_callbacks[i], strlen(php_sw_callbacks[i]), zcallback TSRMLS_CC);
            RETURN_TRUE;
        }
    }

	php_error_docref(NULL TSRMLS_CC, E_WARNING, "swoole_client: event callback[%s] is unknow", cb_name);
	RETURN_FALSE;
}

PHP_FUNCTION(swoole_client_select)
{
	zval *r_array, *w_array, *e_array;
	fd_set rfds, wfds, efds;

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

	if (r_array != NULL) sets += client_event_add(r_array, &rfds, &max_fd TSRMLS_CC);
	if (w_array != NULL) sets += client_event_add(w_array, &wfds, &max_fd TSRMLS_CC);
	if (e_array != NULL) sets += client_event_add(e_array, &efds, &max_fd TSRMLS_CC);

	if (!sets)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "no resource arrays were passed to select");
		RETURN_FALSE;
	}

	if (max_fd >= FD_SETSIZE)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "select max_fd > FD_SETSIZE[%d]", FD_SETSIZE);
		RETURN_FALSE;
	}
	timeo.tv_sec = (int) timeout;
	timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);

	retval = select(max_fd + 1, &rfds, &wfds, &efds, &timeo);

	if (retval == -1)
	{
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errno TSRMLS_CC);
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to select. Error: %s [%d]", strerror(errno), errno);
		RETURN_FALSE;
	}
	if (r_array != NULL)
	{
		client_event_loop(r_array, &rfds TSRMLS_CC);
	}
	if (w_array != NULL)
	{
		client_event_loop(w_array, &wfds TSRMLS_CC);
	}
	if (e_array != NULL)
	{
		client_event_loop(e_array, &efds TSRMLS_CC);
	}
	RETURN_LONG(retval);
}

static int client_event_loop(zval *sock_array, fd_set *fds TSRMLS_DC)
{
	zval **element = NULL;
	zval *zsock;
	zval **dest_element;
	HashTable *new_hash;
	zend_class_entry *ce;

	char *key = NULL;
	int num = 0;
	ulong num_key = 0;
	uint key_len = 0;

	if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
	{
		return 0;
	}
	ALLOC_HASHTABLE(new_hash);
	zend_hash_init(new_hash, zend_hash_num_elements(Z_ARRVAL_P(sock_array)), NULL, ZVAL_PTR_DTOR, 0);
        WRAPPER_ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(sock_array), *element)
		ce = Z_OBJCE_P(*element);
		zsock = sw_zend_read_property(ce, *element, SW_STRL("sock")-1, 0 TSRMLS_CC);
		if (zsock == NULL || ZVAL_IS_NULL(zsock))
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "object is not swoole_client object.");
			continue;
		}
            if ((Z_LVAL(*zsock) < FD_SETSIZE) && FD_ISSET(Z_LVAL(*zsock), fds))
            {
                switch (wrapper_zend_hash_get_current_key(Z_ARRVAL_P(sock_array), &key, &key_len, &num_key))
                {
                case HASH_KEY_IS_STRING:
                    sw_zend_hash_add(new_hash, key, key_len, (void * )element, sizeof(zval *), (void ** )&dest_element);
                    break;
                case HASH_KEY_IS_LONG:
                    sw_zend_hash_index_update(new_hash, num_key, (void * )element, sizeof(zval *), (void ** )&dest_element);
                    break;
                }
                if (dest_element)
                {
                    sw_zval_add_ref(dest_element);
                }
            }
                    num++;
        WRAPPER_ZEND_HASH_FOREACH_END();

	zend_hash_destroy(Z_ARRVAL_P(sock_array));
	efree(Z_ARRVAL_P(sock_array));

	zend_hash_internal_pointer_reset(new_hash);
	Z_ARRVAL_P(sock_array) = new_hash;

	return num ? 1 : 0;
}

static int client_event_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC)
{
	zval **element = NULL;
	zval *zsock;
	zend_class_entry *ce;

	int num = 0;
	if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
	{
		return 0;
	}
	 WRAPPER_ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(sock_array), *element)
		ce = Z_OBJCE_P(*element);
		zsock = sw_zend_read_property(ce, *element, SW_STRL("sock")-1, 0 TSRMLS_CC);
		if (zsock == NULL || ZVAL_IS_NULL(zsock))
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "object is not swoole_client object.");
			continue;
		}
		if (Z_LVAL(*zsock) < FD_SETSIZE)
		{
			FD_SET(Z_LVAL(*zsock), fds);
		}
		else
		{
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "socket[%ld] > FD_SETSIZE[%d].", Z_LVAL(*zsock), FD_SETSIZE);
			continue;
		}
		if (Z_LVAL(*zsock) > *max_fd)
		{
			*max_fd = Z_LVAL(*zsock);
		}
		num++;
	WRAPPER_ZEND_HASH_FOREACH_END();
	return num ? 1 : 0;
}
