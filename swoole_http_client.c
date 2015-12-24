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
  | Author: Fang  <coooold@live.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "thirdparty/php_http_parser.h"
#include "ext/standard/basic_functions.h"

#define SW_FD_HTTP_CLIENT (SW_FD_USER+1)

typedef struct
{
    zval *onFinish;
    zval *onClose;
    zval *onError;
    
    zval* gc_list[128];
    uint gc_idx;
} http_client_callback;

typedef struct
{
    swClient *cli;
    char *host;
    zend_size_t host_len;
    long port;
    double timeout;
    char* uri;
    zend_size_t uri_len;
    
    char *tmp_header_field_name;
    zend_size_t tmp_header_field_name_len;
    
    php_http_parser parser;
    
    int phase;  //0 wait 1 ready 2 busy
    int keep_alive;  //0 no 1 keep

} http_client;

static int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_message_complete(php_http_parser *parser);

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_client_parser_on_header_field,
    http_client_parser_on_header_value,
    NULL,
    http_client_parser_on_body,
    http_client_parser_on_message_complete
};


static PHP_METHOD(swoole_http_client, __construct);
static PHP_METHOD(swoole_http_client, __destruct);
static PHP_METHOD(swoole_http_client, set);
static PHP_METHOD(swoole_http_client, execute);
static PHP_METHOD(swoole_http_client, isConnected);
static PHP_METHOD(swoole_http_client, close);
static PHP_METHOD(swoole_http_client, on);

static int http_client_close(zval *zobject, int fd TSRMLS_DC);
static void http_client_free(zval *object, http_client *http);

static int http_client_onRead(swReactor *reactor, swEvent *event);
static int http_client_onWrite(swReactor *reactor, swEvent *event);
static int http_client_onError(swReactor *reactor, swEvent *event);

static void http_swClient_check_setting(swClient *cli, zval *zset TSRMLS_DC);
static int http_client_error_callback(zval *zobject, swEvent *event, int error TSRMLS_DC);
static int http_client_send_http_request(zval *zobject TSRMLS_DC);
static http_client* http_client_create(zval *object);
static swClient* http_client_create_socket(zval *object, char *host, int host_len, int port);

static zval* http_client_get_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC);
static void http_client_set_cb(zval *zobject, char *cb_name, int cb_name_len, zval *zcb TSRMLS_DC);
static int http_client_check_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC);

static zval* http_client_get_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC)
{
    return sw_zend_read_property(
        swoole_http_client_class_entry_ptr, 
        zobject, cb_name, cb_name_len, 1 TSRMLS_DC);
}

static void http_client_set_cb(zval *zobject, char *cb_name, int cb_name_len, zval *zcb TSRMLS_DC)
{
    if(zcb == NULL)
    {
        zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, cb_name, cb_name_len TSRMLS_CC);
        return;
    }
    
    sw_zval_add_ref(&zcb);
    zend_update_property(swoole_http_client_class_entry_ptr, zobject, cb_name, cb_name_len, zcb TSRMLS_CC);
    
    http_client_callback *hcc = swoole_get_property(zobject, 0);
    if(hcc->gc_idx >= 128)
    {
        swoole_php_fatal_error(E_ERROR, "Too many callbacks");
    }
    
    hcc->gc_list[hcc->gc_idx++] = zcb;
}

static int http_client_check_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC)
{
    zval *cb = http_client_get_cb(zobject, cb_name, cb_name_len TSRMLS_CC);
    if(!cb)
    {
        swoole_php_fatal_error(E_WARNING, "no %s callback was set.", cb_name);
        return -1;
    }
    
    return 0;
}


static const zend_function_entry swoole_http_client_methods[] =
{
    PHP_ME(swoole_http_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http_client, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, execute, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, on, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


zend_class_entry swoole_http_client_ce;
zend_class_entry *swoole_http_client_class_entry_ptr;

void swoole_http_client_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http_client_ce, "swoole_http_client", swoole_http_client_methods);
    swoole_http_client_class_entry_ptr = zend_register_internal_class(&swoole_http_client_ce TSRMLS_CC);

    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

}

/**
 * @zobject: swoole_http_client object
 */
static int http_client_close(zval *zobject, int fd TSRMLS_DC)
{
    //printf("http_client_close()\n");
    zval *zcallback = NULL;
    zval *retval = NULL;
    zval **args[1];

    http_client *http = swoole_get_object(zobject);
    if (!http || !http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }

    //remove from reactor
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, fd);
    }

    if(http->cli->socket->closed)
    {
        return SW_OK;
    }
 
    http->cli->socket->active = 0;
    http->cli->socket->closed = 1;

    zcallback = http_client_get_cb(zobject, ZEND_STRL("close") TSRMLS_CC);
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_client->close[3]: no close callback.");
    }
    args[0] = &zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC)  == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_client->close[4]: onClose handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    //free the callback return value
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    //printf("sw_zval_ptr_dtor(&zobject);\n");
    sw_zval_ptr_dtor(&zobject);
    return SW_OK;
}

static void http_client_free(zval *object, http_client *http)
{
    //printf("http_client_free()\n");
    if (!http)
    {
        return;
    }
    swoole_set_object(object, NULL);

    if(http->cli){

        
        // if(http->cli->server_str)
        // {
        //     sw_free(http->cli->server_str);
        // }
        // if (http->cli->buffer)
        // {
        //     swString_free(http->cli->buffer);
        //     http->cli->buffer = NULL;
        // }

#if PHP_MAJOR_VERSION >= 7
        //for php7 object was allocated sizeof(zval) when execute
        if(http->cli->socket->object)
        {
            //printf("free http->cli->socket->object\n");
            efree(http->cli->socket->object);
        }
#endif
        http->cli->socket->object = NULL;
        
        //close connect when __destruct
        if (http->cli->socket->fd != 0)
        {
            //printf("http->cli->close()\n");
            http->cli->close(http->cli);
        }
        
        //printf("free http->cli\n");
        efree(http->cli);
    }
    //printf("free http\n");
    efree(http);
}

static int http_client_onRead(swReactor *reactor, swEvent *event)
{
    //printf("http_client_onRead() start\n");
    int n;
    zval *zobject;
    char *buf = NULL;
    long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zobject = (zval*)event->socket->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }

#ifdef SW_CLIENT_RECV_AGAIN
    recv_again:
#endif
    buf = emalloc(buf_len + 1);
    n = swConnection_recv(event->socket, buf, buf_len, 0);
    //printf("received %d b\n", n);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", event->fd);
            goto free_buf;
        case SW_CLOSE:
            goto close_cli;
        case SW_WAIT:
            goto free_buf;
        default:
            goto free_buf;
        }
    }
    else if (n == 0)
    {
        goto close_cli;
    }
    else
    {
        long parsed_n = php_http_parser_execute(&http->parser, &http_parser_settings, buf, n);

        //if parsing error happens
        if(parsed_n<0){
            swSysError("Parsing http over socket[%d] failed.", event->fd);
            goto close_cli;
        }

#ifdef SW_CLIENT_RECV_AGAIN
        if (n == SW_CLIENT_BUFFER_SIZE)
        {
            goto recv_again;
        }
#endif

    //printf("http_client_onRead() end\n");
        if (buf)
        {
            efree(buf);
        }
        return SW_OK;
    }

free_buf:
    efree(buf);
    return SW_OK;

close_cli:
    if (buf)
    {
        efree(buf);
    }
    //printf("close_cli: http_client_onRead() start\n");
    return http_client_close(zobject, event->fd TSRMLS_CC);
}


static int http_client_onError(swReactor *reactor, swEvent *event)
{
    zval *zobject = event->socket->object;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int error;
    socklen_t len = sizeof(error);

    if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client->onError[2]: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
    }
    http_client_error_callback(zobject, event, error TSRMLS_CC);
    return SW_OK;
}

static void http_swClient_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    int value;
    HashTable *vht;
    zval *v;

    vht = Z_ARRVAL_P(zset);
    /**
     * socket send/recv buffer size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("socket_buffer_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        swSocket_set_buffer_size(cli->socket->fd, value);
    }

    /**
     * socket send/recv buffer size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("socket_buffer_size"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        swSocket_set_buffer_size(cli->socket->fd, value);
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
}

static int http_client_onWrite(swReactor *reactor, swEvent *event)
{
    zval *zobject = event->socket->object;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }

    if (http->cli->socket->active)
    {
        return swReactor_onWrite(SwooleG.main_reactor, event);
    }
    else
    {
        int error;
        socklen_t len = sizeof(error);

        if (getsockopt (event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_http_client: getsockopt[sock=%d] failed. Error: %s[%d]", event->fd, strerror(errno), errno);
            return SW_ERR;
        }
        //success
        if (error == 0)
        {
            //listen read event
            SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, SW_FD_HTTP_CLIENT | SW_EVENT_READ);
            //connected
            http->cli->socket->active = 1;

            //send http request on write
            http_client_send_http_request(zobject TSRMLS_CC);
        }
        else
        {
            return http_client_error_callback(zobject, event, error TSRMLS_CC);
        }
    }
    return SW_OK;
}

static int http_client_send_http_request(zval *zobject TSRMLS_DC)
{
    http_client *http = swoole_get_object(zobject);
    
    
    
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }
    
    if (http->cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        return SW_ERR;
    }
    
    if (http->phase != 1)
    {
        swoole_php_error(E_WARNING, "http client is not ready.");
        return SW_ERR;
    }
    
    http->phase = 2;
     //clear errno
    SwooleG.error = 0;
    int ret;
    
    char *data;
    zend_size_t data_len;
    int flags = MSG_DONTWAIT;  //http://www.cnblogs.com/blankqdb/archive/2012/08/30/2663859.html
    
    char *keep_alive_str[2] = {"\r\nConnection:closed", "\r\nConnection:keep-alive"};
    
    data = (char*)emalloc(4096*sizeof(char));
    snprintf(data, 1023, "GET %s HTTP/1.1\r\nHost:%s\r\nUser-Agent:swoole_http_client1.0%s\r\n\r\n", 
        http->uri, http->host, keep_alive_str[http->keep_alive]);
    data_len = strlen(data);

    ret = http->cli->send(http->cli, data, data_len, flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, data_len);
        zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
    }
    
    efree(data);
    
    return ret;
}



static int http_client_error_callback(zval *zobject, swEvent *event, int error TSRMLS_DC)
{
    zval *zcallback;
    zval *retval = NULL;
    zval **args[1];

    if (error != 0)
    {
        http_client *http = swoole_get_object(zobject);
        if (http)
        {
            swoole_php_fatal_error(E_WARNING, "connect to server [%s:%ld] failed. Error: %s [%d].", http->host, http->port, strerror(error), error);
        }
    }

    SwooleG.main_reactor->del(SwooleG.main_reactor, event->fd);

    zcallback = http_client_get_cb(zobject, ZEND_STRL("error") TSRMLS_CC);
    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), error TSRMLS_CC);

    args[0] = &zobject;
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_WARNING, "object have not error callback.");
        return SW_ERR;
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onError handler error");
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    
    //printf("sw_zval_ptr_dtor(&zobject) on error;\n");
    sw_zval_ptr_dtor(&zobject);
    return SW_OK;
}


static void php_http_client_swoole_check_reactor()
{
    if (SwooleWG.reactor_init)
    {
        return;
    }

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "async-io must use in cli environment.");
        return;
    }

    if (swIsTaskWorker())
    {
        swoole_php_fatal_error(E_ERROR, "cannot use async-io in task process.");
        return;
    }

    if (SwooleG.main_reactor == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Swoole reactor is not started");
        return;
    }

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_READ, http_client_onRead);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_WRITE, http_client_onWrite);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, (SW_FD_USER + 1) | SW_EVENT_ERROR, http_client_onError);

    php_swoole_event_init();

    SwooleWG.reactor_init = 1;
}

static http_client* http_client_create(zval *object){
    zval *ztmp;
    http_client *http;
    HashTable *vht;

    
    http = (http_client*) emalloc(sizeof(http_client));
    bzero(http, sizeof(http_client));
    
    swoole_set_object(object, http);

    php_http_parser_init(&http->parser, PHP_HTTP_RESPONSE);
    http->parser.data = http;
    
    ztmp = sw_zend_read_property(
        swoole_http_client_class_entry_ptr, 
        object, ZEND_STRL("host"), 0 TSRMLS_CC);
    http->host = Z_STRVAL_P(ztmp);
    http->host_len = Z_STRLEN_P(ztmp);
    ztmp = sw_zend_read_property(
        swoole_http_client_class_entry_ptr, 
        object, ZEND_STRL("port"), 0 TSRMLS_CC);
    convert_to_long(ztmp);
    http->port = Z_LVAL_P(ztmp);

    http->timeout = SW_CLIENT_DEFAULT_TIMEOUT;
    http->keep_alive = 0;
    
    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if(zset)
    {
        vht = Z_ARRVAL_P(zset);
        /**
        * timeout
        */
        if (sw_zend_hash_find(vht, ZEND_STRS("timeout"), (void **) &ztmp) == SUCCESS)
        {
            http->timeout = (double) Z_DVAL_P(ztmp);
        }
        /**
        * keep_alive
        */
        if (sw_zend_hash_find(vht, ZEND_STRS("keep_alive"), (void **) &ztmp) == SUCCESS)
        {
            http->keep_alive = (int) Z_LVAL_P(ztmp);
        }
    }

    http->phase = 1;

    return http;
}

static swClient* http_client_create_socket(zval *object, char *host, int host_len, int port)
{
    int async = 1;
    char conn_key[SW_LONG_CONNECTION_KEY_LEN];
    int conn_key_len = 0;


#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    //http connection must be tcp & async & ~packet_mode
    long type = ((SW_SOCK_TCP) | (SW_FLAG_ASYNC)) & (~SW_MODE_PACKET);

    swClient* cli = (swClient*) emalloc(sizeof(swClient));

    bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);
    conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s:%d", host, port) + 1;
    

    if (swClient_create(cli, php_swoole_socktype(type), async) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "create failed. Error: %s [%d]", strerror(errno), errno);
        zend_update_property_long(swoole_http_client_class_entry_ptr, object, ZEND_STRL("errCode"), errno TSRMLS_CC);
        return NULL;
    }

    // //don't forget free it
    // cli->server_str = strdup(conn_key);
    // cli->server_strlen = conn_key_len;
    
    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        http_swClient_check_setting(cli, zset TSRMLS_CC);
    }
    

    zend_update_property_long(swoole_http_client_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);
    return cli;
}

static PHP_METHOD(swoole_http_client, __construct)
{
#if PHP_MEMORY_DEBUG
    php_vmstat.new_http_client++;
#endif

#if PHP_MAJOR_VERSION >= 7
    swoole_php_fatal_error(E_WARNING, "swoole_http_client is not supported on php7+");
#endif

    char *host;
    zend_size_t host_len;
    long port = 80;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &host, &host_len, &port) == FAILURE)
    {
        return;
    }
    
    if(host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(
        swoole_http_client_class_entry_ptr,
        getThis(), ZEND_STRL("host"), host, host_len TSRMLS_DC);
    
    zend_update_property_long(
        swoole_http_client_class_entry_ptr,
        getThis(), ZEND_STRL("port"), port TSRMLS_DC);

    php_http_client_swoole_check_reactor();

    //init
    swoole_set_object(getThis(), NULL);
    
    zval *headers;
    SW_MAKE_STD_ZVAL(headers);
    array_init(headers);
    zend_update_property(
        swoole_http_client_class_entry_ptr,
        getThis(), ZEND_STRL("headers"), headers TSRMLS_DC);
    
    zval *body;
    SW_MAKE_STD_ZVAL(body);
    ZVAL_STRING(body,"",1);
    zend_update_property(
        swoole_http_client_class_entry_ptr,
        getThis(), ZEND_STRL("body"), body TSRMLS_DC);
    
    http_client_callback *hcc;
    hcc = (http_client_callback*)emalloc(sizeof(http_client_callback));
    bzero(hcc, sizeof(http_client_callback));
    swoole_set_property(getThis(), 0, hcc);
    
    RETURN_TRUE;
}



static PHP_METHOD(swoole_http_client, __destruct)
{
    zval *headers = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("headers"), 0 TSRMLS_CC);
    zval *body = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("body"), 0 TSRMLS_CC);
    
    sw_zval_ptr_dtor(&headers);
    sw_zval_ptr_dtor(&body);
    
    http_client_set_cb(getThis(), ZEND_STRL("finish"), NULL TSRMLS_CC);
    http_client_set_cb(getThis(), ZEND_STRL("close"), NULL TSRMLS_CC);
    http_client_set_cb(getThis(), ZEND_STRL("error"), NULL TSRMLS_CC);
    
    http_client_callback *hcc = swoole_get_property(getThis(), 0);
    int i;
    for(i=0;i<hcc->gc_idx;i++)
    {
        zval *zcb = hcc->gc_list[i];
        sw_zval_ptr_dtor(&zcb);
    }
    efree(hcc);
    swoole_set_property(getThis(), 0, NULL);
    
    //printf("zim_swoole_http_client___destruct()\n");
    http_client *http = swoole_get_object(getThis());
    if (http)
    {
        http_client_free(getThis(), http);
    }
}

static PHP_METHOD(swoole_http_client, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

//$http_client->execute();
static PHP_METHOD(swoole_http_client, execute)
{
    int ret;
    long sock_flag = 0;
    http_client *http = NULL;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb;
    int reactor_flag = 0;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        return;
    }


    http = swoole_get_object(getThis());
    if (http)   //http is not null when keeping alive
    {
        if(http->phase != 1
            || http->cli->socket->active != 1
            || http->keep_alive != 1
        ) //http not ready
        {
            swoole_php_fatal_error(E_ERROR, "Operation now in progress phase %d.", http->phase);
            
            swEvent e;
            e.fd = http->cli->socket->fd;
            e.socket = http->cli->socket;
            http_client_error_callback(getThis(), &e, errno TSRMLS_CC);

            RETURN_FALSE;
        }
    }
    else
    {
        http = http_client_create(getThis());
    }

    if(http == NULL)
    {
        RETURN_FALSE;
    }

    
    if(uri_len <= 0)
    {
        RETURN_FALSE;
    }

    http->uri = uri;
    http->uri_len = uri_len;
    
    if (finish_cb == NULL || ZVAL_IS_NULL(finish_cb))
    {
        swoole_php_fatal_error(E_WARNING, "finish callback is not set.");
    }
    http_client_set_cb(getThis(), ZEND_STRL("finish"), finish_cb TSRMLS_CC);
    
    if(http->cli)   //if connection exists
    {
        http_client_send_http_request(getThis() TSRMLS_CC);
        RETURN_TRUE;
    }
    
    
    http->cli = http_client_create_socket(getThis(), http->host, http->host_len, http->port);
    if (http->cli == NULL)
    {
        RETURN_FALSE;
    }

    if (http->cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client is already connected.");
        RETURN_FALSE;
    }

    sock_flag = 1;  //async

    ret = http->cli->connect(http->cli, http->host, http->port, http->timeout, sock_flag);

 
    if(0 != http_client_check_cb(getThis(), ZEND_STRL("finish")) TSRMLS_CC)
    {
        RETURN_FALSE;
    }
    
    if(0 != http_client_check_cb(getThis(), ZEND_STRL("error")) TSRMLS_CC)
    {
        RETURN_FALSE;
    }

    //printf("errorno %d  EINPROGRESS %d ret %d\n", errno, EINPROGRESS, ret);

    zval *obj = getThis();
#if PHP_MAJOR_VERSION >= 7
    http->cli->socket->object = (zval *)emalloc(sizeof(zval));
    ZVAL_DUP(http->cli->socket->object,obj);
#else
    http->cli->socket->object = obj;
    sw_zval_add_ref(&obj);
#endif

    http->cli->reactor_fdtype = SW_FD_HTTP_CLIENT;

    reactor_flag = http->cli->reactor_fdtype | SW_EVENT_WRITE;
    if (errno == EINPROGRESS)
    {
        ret = SwooleG.main_reactor->add(SwooleG.main_reactor, http->cli->socket->fd, reactor_flag);
        SW_CHECK_RETURN(ret);
    }
    else
    {
        swEvent e;
        e.fd = http->cli->socket->fd;
        e.socket = http->cli->socket;
        http_client_error_callback(getThis(), &e, errno TSRMLS_CC);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, isConnected)
{
    http_client *http = swoole_get_object(getThis());
    if (!http->cli)
    {
        RETURN_FALSE;
    }
    if (!http->cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(http->cli->socket->active);
}

static PHP_METHOD(swoole_http_client, close)
{
    int ret = 1;

    http_client *http = swoole_get_object(getThis());
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        RETURN_FALSE;
    }

    if (!http->cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }

    if (http->cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "client socket is closed.");
        RETURN_FALSE;
    }

    if (http->cli->async == 1 && SwooleG.main_reactor != NULL)
    {
        ret = http_client_close(getThis(), http->cli->socket->fd TSRMLS_CC);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, on)
{
    char *cb_name;
    zend_size_t cb_name_len;
    zval *zcallback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
    {
        return;
    }
    
    if(strncasecmp("finish", cb_name, cb_name_len) == 0
            || strncasecmp("error", cb_name, cb_name_len) == 0
            || strncasecmp("close", cb_name, cb_name_len) == 0
    )
    {
        http_client_set_cb(getThis(), cb_name, cb_name_len, zcallback TSRMLS_CC);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client: event callback[%s] is unknow", cb_name);
        RETURN_FALSE;
    }
    
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), cb_name, cb_name_len, zcallback TSRMLS_CC);

    RETURN_TRUE;
}









static int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    http_client* http = (http_client*)parser->data;
    //zval* zobject = (zval*)http->cli->socket->object;

    http->tmp_header_field_name = (char *)at;
    http->tmp_header_field_name_len = length;
    return 0;
}


static int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client* http = (http_client*)parser->data;
    zval* zobject = (zval*)http->cli->socket->object;
    
    zval *headers;
    
    headers = sw_zend_read_property(
        swoole_http_client_class_entry_ptr, 
        zobject, ZEND_STRL("headers"), 0 TSRMLS_DC);
    
    char *header_name = zend_str_tolower_dup(http->tmp_header_field_name, http->tmp_header_field_name_len);
    sw_add_assoc_stringl_ex(headers, header_name, http->tmp_header_field_name_len + 1, (char *) at, length, 1);
    efree(header_name);
    return 0;
}

static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client* http = (http_client*)parser->data;
    zval* zobject = (zval*)http->cli->socket->object;
    
    zval *body = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("body"), 0 TSRMLS_CC);
    zval *tmp;
    SW_MAKE_STD_ZVAL(tmp);
    ZVAL_STRINGL(tmp, at, length, 1);
    add_string_to_string(body, body, tmp);
    sw_zval_ptr_dtor(&tmp);

    return 0;
}

static int http_client_parser_on_message_complete(php_http_parser *parser)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    http_client* http = (http_client*)parser->data;
    zval* zobject = (zval*)http->cli->socket->object;

    if(http->keep_alive == 1)
    {
        //reset http phase for reuse
        http->phase = 1;
    }


    zval *retval;
    zval *zcallback;

    zcallback = http_client_get_cb(zobject, ZEND_STRL("finish") TSRMLS_CC);

    zval **args[1];
    args[0] = &zobject;
    
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client object have not receive callback.");
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onReactorCallback handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return 0;
}
