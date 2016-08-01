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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

#ifdef SW_COROUTINE

#include "swoole_coroutine.h"
#include "ext/standard/basic_functions.h"
#include <setjmp.h>

#ifdef SW_DEBUG
static int request_cnt;
#endif

static PHP_METHOD(swoole_client_coro, __construct);

static PHP_METHOD(swoole_client_coro, __destruct);

static PHP_METHOD(swoole_client_coro, connect);

static PHP_METHOD(swoole_client_coro, recv);

static PHP_METHOD(swoole_client_coro, send);

static PHP_METHOD(swoole_client_coro, sendfile);

static PHP_METHOD(swoole_client_coro, sendto);


static PHP_METHOD(swoole_client_coro, isConnected);

static PHP_METHOD(swoole_client_coro, getsockname);

static PHP_METHOD(swoole_client_coro, getpeername);

static PHP_METHOD(swoole_client_coro, close);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client_coro, getSocket);
#endif

static void client_coro_onConnect(swClient *cli);

static void client_coro_onReceive(swClient *cli, char *data, uint32_t length);

static int client_coro_onPackage(swConnection *conn, char *data, uint32_t length);

static void client_coro_onClose(swClient *cli);

static void client_coro_onError(swClient *cli);

static void client_coro_onTimeout(php_context *cxt);

static void php_swoole_client_coro_free(zval *object, swClient *cli TSRMLS_DC);

#define CLIENT_RUNING  0
#define CLIENT_IOWAIT  1
#define CLIENT_READY   2
#define CLIENT_ERROR 3

typedef struct
{
    php_context context;
    uint8_t status;
} swoole_client_coro_property;

static sw_inline void client_free_php_context(zval *object)
{
    //free memory
    swoole_client_coro_property *property = swoole_get_property(object, 0);
    if (!property)
    {
        return;
    }
    efree(property);
    swString *buffer = swoole_get_property(object, 1);
    if (!buffer)
    {
        return;
    }
    efree(buffer);
    swoole_set_property(object, 0, NULL);
}

static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC);

static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client_coro, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client_coro, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recv, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, send, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendfile, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendto, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getsockname, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getpeername, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, close, NULL, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_client_coro, getSocket, NULL, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
        };

static swHashMap *php_sw_long_connections;

zend_class_entry swoole_client_coro_ce;
zend_class_entry *swoole_client_coro_class_entry_ptr;

void swoole_client_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_client_coro_ce, "swoole_client_coro", "Swoole\\Coroutine\\Client", swoole_client_coro_methods);
    swoole_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_client_coro_ce TSRMLS_CC);

    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("errCode") - 1, 0, ZEND_ACC_PUBLIC
                               TSRMLS_CC);
    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("sock") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_client_coro_class_entry_ptr, SW_STRL("reuse") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    php_sw_long_connections = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);

    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT
                                     TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL
                                     TSRMLS_CC);
}

static int client_coro_onPackage(swConnection *conn, char *data, uint32_t length)
{
    client_coro_onReceive(conn->object, data, length);
    return SW_OK;
}

static void client_coro_onReceive(swClient *cli, char *data, uint32_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

#ifdef SW_DEBUG
    ++request_cnt;
    swTrace("client on receive %d", request_cnt);
#endif

    zval *zobject = cli->object;
    zval *retval = NULL;

    zval * zdata;

    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
    }

    swoole_client_coro_property *sw_current_context = swoole_get_property(zobject, 0);
    if (sw_current_context->status != CLIENT_IOWAIT)
    {
        swString *buffer = swoole_get_property(zobject, 1);
        if (buffer == NULL)
        {
            buffer = swString_new(length);
            swoole_set_property(zobject, 1, buffer);
        }
        swString_append_ptr(buffer, data, length);
        sw_current_context->status = CLIENT_READY;
        return;
    }

    SW_MAKE_STD_ZVAL(zdata);
    SW_ZVAL_STRINGL(zdata, data, length, 1);
    sw_current_context->status = CLIENT_RUNING;
    int ret = coro_resume((php_context *)sw_current_context, zdata, &retval);

    if (ret > 0)
    {
        goto free_zdata;
    }
    if (retval != NULL) {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void client_coro_onConnect(swClient *cli)
{
    if (!swSocket_is_stream(cli->type))
    {
        return;
    }
    zval * zdata;
    zval * retval;

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 1);
    zval * zobject = cli->object;
    swoole_client_coro_property *sw_current_context = swoole_get_property(zobject, 0);
    sw_current_context->status = CLIENT_RUNING;
    int ret = coro_resume(&(sw_current_context->context), zdata, &retval);

    if (ret > 0) {
        goto free_zdata;

    }
    if (retval != NULL) {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void client_coro_onClose(swClient *cli)
{
    return;
}

static void client_coro_onError(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval * zdata;
    zval * retval;
    zval * zobject = cli->object;
    swoole_client_coro_property *property = swoole_get_property(zobject, 0);
    zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);

    if (property->status != CLIENT_IOWAIT)
    {
        property->status = CLIENT_ERROR;
        return;
    }

	if (cli->timeout_id > 0)
	{
		php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
	}

	//close connection
	php_swoole_client_coro_free(zobject, cli TSRMLS_CC);

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 0);
    int ret = coro_resume((php_context*)property, zdata, &retval);

    if (ret > 0)
    {
        goto free_zdata;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
   free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void client_coro_onTimeout(php_context *ctx)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zdata;
    zval *retval;

    zval *zobject = (zval *)ctx->coro_params;
    zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), 110 TSRMLS_CC);

	//timeout close connection
    swClient *cli = swoole_get_object(zobject);
	php_swoole_client_coro_free(zobject, cli TSRMLS_CC);

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 0);
    int ret = coro_resume(ctx, zdata, &retval);

    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    HashTable * vht;
    zval * v;
    int value = 1;

    vht = Z_ARRVAL_P(zset);

    //buffer: check eof
    if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_split"), (void **) &v) == SUCCESS
        || sw_zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        cli->open_eof_check = Z_BVAL_P(v);
        cli->protocol.split_by_eof = 1;
    }
    //package eof
    if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        cli->protocol.package_eof_len = Z_STRLEN_P(v);
        if (cli->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            return;
        }
        bzero(cli->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(cli->protocol.package_eof, Z_STRVAL_P(v), Z_STRLEN_P(v));
        cli->protocol.onPackage = client_coro_onPackage;
    }
    //open length check
    if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        cli->open_length_check = Z_BVAL_P(v);
        cli->protocol.get_package_length = swProtocol_get_package_length;
        cli->protocol.onPackage = client_coro_onPackage;
    }
    //package length size
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        cli->protocol.package_length_type = Z_STRVAL_P(v)[0];
        cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

        if (cli->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            return;
        }
    }
    //package length offset
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        cli->protocol.package_length_offset = (int) Z_LVAL_P(v);
    }
    //package body start
    if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &v) == SUCCESS)
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
    /**
     * socket send/recv buffer size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("socket_buffer_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        swSocket_set_buffer_size(cli->socket->fd, value);
        cli->socket->buffer_size = cli->buffer_input_size = value;
    }
    /**
     * TCP_NODELAY
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **) &v) == SUCCESS)
    {
        value = 1;
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0)
        {
            swSysError("setsockopt(%d, TCP_NODELAY) failed.", cli->socket->fd);
        }
    }
#ifdef SW_USE_OPENSSL
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_method"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        cli->ssl_method = (int) Z_LVAL_P(v);
        cli->open_ssl = 1;
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_compress"), (void **) &v) == SUCCESS)
    {
        convert_to_boolean(v);
        cli->ssl_disable_compress = !Z_BVAL_P(v);
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        cli->ssl_cert_file = strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_cert_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", cli->ssl_cert_file);
            return;
        }
        cli->open_ssl = 1;
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &v) == SUCCESS)
    {
        convert_to_string(v);
        cli->ssl_key_file = strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_key_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", cli->ssl_key_file);
            return;
        }
    }
    if (cli->ssl_cert_file && !cli->ssl_key_file)
    {
        swoole_php_fatal_error(E_ERROR, "ssl require key file.");
        return;
    }
#endif
}

static void php_swoole_client_coro_free(zval *object, swClient *cli TSRMLS_DC)
{
    //long tcp connection, delete from php_sw_long_connections
    if (cli->keep)
    {
        if (swHashMap_del(php_sw_long_connections, cli->server_str, cli->server_strlen))
        {
            swoole_php_fatal_error(E_WARNING, "delete from hashtable failed.");
        }
        efree(cli->server_str);
        swClient_free(cli);
        pefree(cli, 1);
    }
    else
    {
        efree(cli->server_str);
        swClient_free(cli);
        efree(cli);
    }
    //unset object
    swoole_set_object(object, NULL);
}

static swClient *php_swoole_client_coro_new(zval *object, char *host, int host_len, int port)
{
    zval * ztype;
    int async = 0;
    char conn_key[SW_LONG_CONNECTION_KEY_LEN];
    int conn_key_len = 0;
    uint64_t tmp_buf;
    int ret;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    ztype = sw_zend_read_property(swoole_client_coro_class_entry_ptr, object, SW_STRL("type") - 1, 0 TSRMLS_CC);

    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get swoole_client_coro->type failed.");
        return NULL;
    }

    long type = Z_LVAL_P(ztype);

    //new flag, swoole-1.6.12+
    if (type & SW_FLAG_ASYNC)
    {
        async = 1;
    }

    swClient *cli;

    bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);
    zval * connection_id = sw_zend_read_property(swoole_client_coro_class_entry_ptr, object, ZEND_STRL("id"), 1
                                                 TSRMLS_CC);

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
        swClient *find = swHashMap_find(php_sw_long_connections, conn_key, conn_key_len);
        if (find == NULL)
        {
            cli = (swClient *) pemalloc(sizeof(swClient), 1);
            if (swHashMap_add(php_sw_long_connections, conn_key, conn_key_len, cli) == FAILURE)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_client_coro_create_socket add to hashtable failed.");
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
            //clear history data
            if (ret > 0)
            {
                swSocket_clean(cli->socket->fd);
            }
        }
    }
    else
    {
        cli = (swClient *) emalloc(sizeof(swClient));

        create_socket:
        if (swClient_create(cli, php_swoole_socktype(type), async) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "swClient_create() failed. Error: %s [%d]", strerror(errno), errno);
            zend_update_property_long(swoole_client_coro_class_entry_ptr, object, ZEND_STRL("errCode"), errno
                                      TSRMLS_CC);
            return NULL;
        }

        //don't forget free it
        cli->server_str = estrdup(conn_key);
        cli->server_strlen = conn_key_len;
    }

    zend_update_property_long(swoole_client_coro_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    if (type & SW_FLAG_KEEP)
    {
        cli->keep = 1;
    }

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        cli->open_ssl = 1;
    }
#endif
    return cli;
}

static PHP_METHOD(swoole_client_coro, __construct)
{
	coro_check(TSRMLS_C);

    zval * ztype;
    char *id = NULL;
    zend_size_t len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|s", &ztype, &id, &len) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "require socket type param.");
        RETURN_FALSE;
    }

#if PHP_MEMORY_DEBUG
        php_vmstat.new_client++;
#endif

    Z_LVAL_P(ztype) = Z_LVAL_P(ztype) | SW_FLAG_ASYNC;

    php_swoole_check_reactor();

    zend_update_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), ztype TSRMLS_CC);
    if (id)
    {
        zend_update_property_stringl(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("id"), id, len TSRMLS_CC);
    }
    else
    {
        zend_update_property_null(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("id") TSRMLS_CC);
    }
    //init
    swoole_set_object(getThis(), NULL);
    swoole_client_coro_property *property = (swoole_client_coro_property *)emalloc(sizeof(swoole_client_coro_property));
    property->status = CLIENT_RUNING;
    swoole_set_property(getThis(), 0, property);
    swoole_set_property(getThis(), 1, NULL);
    RETURN_TRUE;
}


static PHP_METHOD(swoole_client_coro, __destruct)
{
    swClient *cli = swoole_get_object(getThis());
    //no keep connection
    if (cli)
    {
        cli->released = 1;
		if (cli->timeout_id > 0)
		{
			php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
			cli->timeout_id = 0;
		}

        if (cli->socket->closed)
        {
            php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);
        }
        else if (!cli->keep)
        {
            cli->close(cli);
            php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);
        }
    }
    //free callback function
    client_free_php_context(getThis());

#if PHP_MEMORY_DEBUG
    php_vmstat.free_client++;
    if (php_vmstat.free_client % 10000 == 0)
    {
        printf("php_vmstat.free_client=%d\n", php_vmstat.free_client);
    }
#endif
}

static PHP_METHOD(swoole_client_coro, connect)
{
    long port = 0, sock_flag = 0;
    char *host = NULL;
    zend_size_t host_len;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ldl", &host, &host_len, &port, &timeout, &sock_flag) ==
        FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "The host is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());

    if (cli && !cli->keep)
    {
        if (!cli->socket->closed)
        {
            cli->close(cli);
        }
        php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);
    }

    cli = php_swoole_client_coro_new(getThis(), host, host_len, port);
    if (cli == NULL)
    {
        RETURN_FALSE;
    }
    cli->timeout=timeout;
    swoole_set_object(getThis(), cli);

    if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
    {
        if (port <= 0 || port > SW_CLIENT_MAX_PORT)
        {
            swoole_php_fatal_error(E_WARNING, "The port is invalid.");
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
        zend_update_property_bool(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("reuse") - 1, 1 TSRMLS_CC);
        RETURN_TRUE;
    }
    else if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_client_coro is already connected.");
        RETURN_FALSE;
    }

    zval * zset = sw_zend_read_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1
                                        TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        client_check_setting(cli, zset TSRMLS_CC);
    }

    cli->onConnect = client_coro_onConnect;
    cli->onClose = client_coro_onClose;
    cli->onError = client_coro_onError;
    cli->onReceive = client_coro_onReceive;

    if (swSocket_is_stream(cli->type))
    {
        cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    }
    else
    {
        cli->reactor_fdtype = PHP_SWOOLE_FD_DGRAM_CLIENT;
    }

    zval * obj = getThis();
#if PHP_MAJOR_VERSION >= 7
    cli->object = (zval *) emalloc(sizeof(zval));
    ZVAL_DUP(cli->object, obj);
#else
    cli->object = obj;
#endif

    //nonblock async
    if (cli->connect(cli, host, port, timeout, sock_flag) < 0)
    {
        swoole_php_error(E_WARNING, "connect to server[%s:%d] failed. Error: %s [%d]", host, (int) port,
                         strerror(errno), errno);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode") - 1, errno
                                  TSRMLS_CC);
        RETURN_FALSE;
    }
    if (swSocket_is_stream(cli->type))
    {
        swoole_client_coro_property *property = swoole_get_property(getThis(), 0);
        if (!property)
        {
            property = emalloc(sizeof(swoole_client_coro_property));
            swoole_set_property(getThis(), 0, property);
        }
        property->context.onTimeout = client_coro_onTimeout;
        property->context.coro_params = getThis();

        coro_save(return_value, return_value_ptr, &property->context);
        property->status = CLIENT_IOWAIT;
        coro_yield();
    }
}

static PHP_METHOD(swoole_client_coro, send)
{
    char *data;
    zend_size_t data_len;
    long flags = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &data, &data_len, &flags) == FAILURE)
    {
        return;
    }

    if (data_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }

    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
    }

    //clear errno
    SwooleG.error = 0;
    int ret = cli->send(cli, data, data_len, flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode") - 1, SwooleG.error
                TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }
}

static PHP_METHOD(swoole_client_coro, sendto)
{
    char *ip;
    char *ip_len;
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
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
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

static PHP_METHOD(swoole_client_coro, sendfile)
{
    char *file;
    zend_size_t file_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &file, &file_len) == FAILURE)
    {
        return;
    }
    if (file_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "file is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
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
        swoole_php_fatal_error(E_WARNING, "sendfile() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode") - 1, SwooleG.error
                TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, recv)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }

    swoole_client_coro_property *property = swoole_get_property(getThis(), 0);
    if (property != NULL && property->status == CLIENT_READY)
    {
        swString *buffer = swoole_get_property(getThis(), 1);
        size_t size = buffer->length;
        buffer->length = 0;
        property->status = CLIENT_RUNING;
        SW_RETURN_STRINGL(buffer->str, size, 1);
    }

    if (property != NULL && property->status == CLIENT_ERROR)
    {
        RETURN_FALSE;
    }
    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
    }

    if (!property)
    {
        property = emalloc(sizeof(swoole_client_coro_property));
        swoole_set_property(getThis(), 0, property);
    }

    //cli->timeout = timeout;
    property->context.onTimeout = client_coro_onTimeout;
    property->context.coro_params = getThis();

    cli->timeout_id = php_swoole_add_timer_coro((int) (cli->timeout * 1000), cli->socket->fd, (void *) &property->context TSRMLS_CC);
    property->status = CLIENT_IOWAIT;
    coro_save(return_value, return_value_ptr, &property->context);
    coro_yield();
}

static PHP_METHOD(swoole_client_coro, isConnected)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->socket->active);
}

static PHP_METHOD(swoole_client_coro, getsockname)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
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
    if (getsockname(cli->socket->fd, (struct sockaddr *) &cli->socket->info.addr, &cli->socket->info.len) < 0)
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

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client_coro, getSocket)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    php_socket *socket_object = swoole_convert_to_socket(cli->socket->fd);
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
}
#endif

static PHP_METHOD(swoole_client_coro, getpeername)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
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

static PHP_METHOD(swoole_client_coro, close)
{
    int ret = 1;
    zend_bool force = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &force) == FAILURE)
    {
        return;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "client socket is closed.");
        RETURN_FALSE;
    }

    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
    }
    //Connection error, or short tcp connection.
    //No keep connection
    if (force || !cli->keep || swConnection_error(SwooleG.error) == SW_CLOSE)
    {
        ret = cli->close(cli);
        php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);
    }
    SW_CHECK_RETURN(ret);
}
#endif
