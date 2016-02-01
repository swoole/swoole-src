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
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"
#include "websocket.h"

#ifdef SW_ASYNC_HTTPCLIENT

static swString *http_client_buffer;

enum http_client_state
{
    HTTP_CLIENT_STATE_WAIT,
    HTTP_CLIENT_STATE_READY,
    HTTP_CLIENT_STATE_BUSY,
    //WebSocket
    HTTP_CLIENT_STATE_UPGRADE,
};

typedef struct
{
    zval* gc_list[128];
    uint gc_idx;

    zval *request_header;
    zval *request_body;
    char *request_method;
    zval *response_header;
    zval *response_body;

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
    
    char *body;

    php_http_parser parser;
    swString *buffer;

    int state: 8;  //0 wait 1 ready 2 busy
    int keep_alive :1;  //0 no 1 keep
    int upgrade :1;

} http_client;

static int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_message_complete(php_http_parser *parser);

static void http_client_onReceive(swClient *cli, char *data, uint32_t length);
static void http_client_onConnect(swClient *cli);
static void http_client_onClose(swClient *cli);
static void http_client_onError(swClient *cli);

static void http_client_free(zval *object, http_client *http);
static int http_client_error_callback(zval *zobject, swEvent *event, int error TSRMLS_DC);
static int http_client_send_http_request(zval *zobject TSRMLS_DC);
static http_client* http_client_create(zval *object TSRMLS_DC);
static int http_client_execute(zval *zobject, char *uri, zend_size_t uri_len, zval *callback TSRMLS_DC);
static zval* http_client_get_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC);
static void http_client_set_cb(zval *zobject, char *cb_name, int cb_name_len, zval *zcb TSRMLS_DC);

static sw_inline void http_client_swString_append_headers(swString* swStr, char* key, zend_size_t key_len, char* data, zend_size_t data_len)
{
    swString_append_ptr(swStr, key, key_len);
    swString_append_ptr(swStr, ZEND_STRL(": "));
    swString_append_ptr(swStr, data, data_len);
    swString_append_ptr(swStr, ZEND_STRL("\r\n"));
}

static sw_inline void http_client_create_token(int length, char *buf)
{
    char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"§$%&/()=[]{}";
    int i;
    assert(length < 1024);
    for (i = 0; i < length; i++)
    {
        buf[i] = characters[rand() % sizeof(characters) - 1];
    }
    buf[length] = '\0';
}

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

zend_class_entry swoole_http_client_ce;
zend_class_entry *swoole_http_client_class_entry_ptr;

static PHP_METHOD(swoole_http_client, __construct);
static PHP_METHOD(swoole_http_client, __destruct);
static PHP_METHOD(swoole_http_client, set);
static PHP_METHOD(swoole_http_client, setHeaders);
static PHP_METHOD(swoole_http_client, setData);
static PHP_METHOD(swoole_http_client, execute);
static PHP_METHOD(swoole_http_client, push);
static PHP_METHOD(swoole_http_client, isConnected);
static PHP_METHOD(swoole_http_client, close);
static PHP_METHOD(swoole_http_client, on);
static PHP_METHOD(swoole_http_client, get);
static PHP_METHOD(swoole_http_client, post);
static PHP_METHOD(swoole_http_client, upgrade);

static const zend_function_entry swoole_http_client_methods[] =
{
    PHP_ME(swoole_http_client, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http_client, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setHeaders, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setData, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, execute, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, push, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, get, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, post, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, upgrade, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, on, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zval* http_client_get_cb(zval *zobject, char *cb_name, int cb_name_len TSRMLS_DC)
{
    return sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, cb_name, cb_name_len, 1 TSRMLS_CC);
}

static void http_client_set_cb(zval *zobject, char *cb_name, int cb_name_len, zval *zcb TSRMLS_DC)
{
    if (zcb == NULL)
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

static int http_client_execute(zval *zobject, char *uri, zend_size_t uri_len, zval *callback TSRMLS_DC)
{
    http_client *http = swoole_get_object(zobject);

    //http is not null when keeping alive
    if (http)
    {
        //http not ready
        if (http->state != HTTP_CLIENT_STATE_READY || http->cli->socket->active != 1 || http->keep_alive != 1)
        {
            swoole_php_fatal_error(E_ERROR, "Operation now in progress phase %d.", http->state);

            swEvent e;
            e.fd = http->cli->socket->fd;
            e.socket = http->cli->socket;
            http_client_error_callback(zobject, &e, errno TSRMLS_CC);

            return SW_ERR;
        }
    }
    else
    {
        http = http_client_create(zobject TSRMLS_CC);
    }

    if (http == NULL)
    {
        return SW_ERR;
    }

    if (uri_len <= 0)
    {
        return SW_ERR;
    }

    http->uri = estrdup(uri);
    http->uri_len = uri_len;

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        swoole_php_fatal_error(E_WARNING, "finish callback is not set.");
    }
    http_client_set_cb(zobject, ZEND_STRL("finish"), callback TSRMLS_CC);

    //if connection exists
    if (http->cli)
    {
        http_client_send_http_request(zobject TSRMLS_CC);
        return SW_OK;
    }

    swClient *cli = php_swoole_client_create_socket(zobject, http->host, http->host_len, http->port);
    if (cli == NULL)
    {
        return SW_ERR;
    }
    http->cli = cli;

    if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client is already connected.");
        return SW_ERR;
    }

    cli->object = zobject;
    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    cli->onReceive = http_client_onReceive;
    cli->onConnect = http_client_onConnect;
    cli->onClose = http_client_onClose;
    cli->onError = http_client_onError;

    return cli->connect(cli, http->host, http->port, http->timeout, 0);
}


void swoole_http_client_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_client_ce, "swoole_http_client", "Swoole\\Http\\Client", swoole_http_client_methods);
    swoole_http_client_class_entry_ptr = zend_register_internal_class(&swoole_http_client_ce TSRMLS_CC);

    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_onClose(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zcallback = NULL;
    zval *retval = NULL;
    zval **args[1];
    zval *zobject = cli->object;

    http_client *http = swoole_get_object(zobject);
    if (!http || !http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }

    if (http->cli->socket->closed)
    {
        return;
    }
 
    zcallback = http_client_get_cb(zobject, ZEND_STRL("close") TSRMLS_CC);
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        return;
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
    sw_zval_ptr_dtor(&zobject);
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_onError(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zcallback = NULL;
    zval *retval = NULL;
    zval **args[1];
    zval *zobject = cli->object;

    http_client *http = swoole_get_object(zobject);
    if (!http || !http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }

    if (http->cli->socket->closed)
    {
        return;
    }

    zcallback = http_client_get_cb(zobject, ZEND_STRL("error") TSRMLS_CC);
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_client->onError[3]: no error callback.");
    }
    args[0] = &zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC)  == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_client->onError[4]: call_user_function failed.");
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
    sw_zval_ptr_dtor(&zobject);
}

static void http_client_free(zval *object, http_client *http)
{
    //printf("http_client_free()\n");
    if (!http)
    {
        return;
    }
    swoole_set_object(object, NULL);

    if (http->cli)
    {

#if PHP_MAJOR_VERSION >= 7
        //for php7 object was allocated sizeof(zval) when execute
        if (http->cli->socket->object)
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
        efree(http->uri);
    }
    //printf("free http\n");
    efree(http);
}

static void http_client_onReceive(swClient *cli, char *data, uint32_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }

    if (http->state == HTTP_CLIENT_STATE_UPGRADE)
    {
        swString *buffer = http->buffer;
        if (swString_append_ptr(buffer, data, length) < 0)
        {
            cli->close(cli);
            return;
        }

        if (cli->socket->recv_wait)
        {
            recv_wait:
            if (buffer->offset == buffer->length)
            {
                zval **args[2];
                zval *retval;

                zval *zframe = php_swoole_websocket_unpack(buffer TSRMLS_CC);

                args[0] = &zobject;
                args[1] = &zframe;

                zval *zcallback = http_client_get_cb(zobject, ZEND_STRL("message") TSRMLS_CC);
                if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC)  == FAILURE)
                {
                    swoole_php_fatal_error(E_ERROR, "swoole_http_client->onMessage: onClose handler error");
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
                sw_zval_ptr_dtor(&zframe);
                cli->socket->recv_wait = 0;
                swString_clear(buffer);
            }
        }
        else
        {
            int package_length = swWebSocket_get_package_length(NULL, cli->socket, data, length);
            //invalid package, close connection.
            if (package_length < 0)
            {
                cli->close(cli);
                return;
            }
            //no length
            else if (package_length == 0)
            {
                return;
            }
            //get length success
            else
            {
                if (buffer->size < package_length)
                {
                    if (swString_extend(buffer, package_length) < 0)
                    {
                        return;
                    }
                }
                buffer->offset = package_length;
                cli->socket->recv_wait = 1;

                goto recv_wait;
            }
        }
    }
    else
    {
        long parsed_n = php_http_parser_execute(&http->parser, &http_parser_settings, data, length);
        if (parsed_n < 0)
        {
            swSysError("Parsing http over socket[%d] failed.", cli->socket->fd);
            cli->close(cli);
        }
    }
}

static void http_client_onConnect(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }
    //send http request on write
    http_client_send_http_request(zobject TSRMLS_CC);
}


#if PHP_MAJOR_VERSION < 7
static inline char* sw_http_build_query(zval *data, zend_size_t *length TSRMLS_DC)
{
    smart_str formstr = {0};

#if PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 3
    if (php_url_encode_hash_ex(HASH_OF(data), &formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL TSRMLS_CC) == FAILURE)
#else
    if (php_url_encode_hash_ex(HASH_OF(data), &formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738 TSRMLS_CC) == FAILURE)
#endif
    {
        if (formstr.c)
        {
            smart_str_free(&formstr);
        }
        return NULL;
    }
    if (!formstr.c)
    {
        return NULL;
    }
    smart_str_0(&formstr);
    *length = formstr.len;
    return formstr.c;
}
#else
static inline char* sw_http_build_query(zval *data, zend_size_t *length TSRMLS_DC)
{
    smart_str formstr = {0};;
    if (php_url_encode_hash_ex(HASH_OF(data), &formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
    {
        if (formstr.s)
        {
            smart_str_free(&formstr);
        }
        return NULL;
    }
    if (!formstr.s)
    {
        return NULL;
    }
    smart_str_0(&formstr);
    *length = formstr.s->len;
    return formstr.s->val;
}
#endif

static int http_client_send_http_request(zval *zobject TSRMLS_DC)
{
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }
    
    if (!http->cli->socket && http->cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        return SW_ERR;
    }
    
    if (http->state != HTTP_CLIENT_STATE_READY)
    {
        swoole_php_error(E_WARNING, "http client is not ready.");
        return SW_ERR;
    }
    
    http->state = HTTP_CLIENT_STATE_BUSY;
     //clear errno
    SwooleG.error = 0;

    http_client_callback *hcc = swoole_get_property(zobject, 0);

    zval *post_data = hcc->request_body;
    zval *send_header = hcc->request_header;

    //POST
    if (post_data)
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "POST";
        }
    }
    //GET
    else
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "GET";
        }
    }

    swString_clear(http_client_buffer);
    swString_append_ptr(http_client_buffer, hcc->request_method, strlen(hcc->request_method));
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));
    swString_append_ptr(http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    char *key;
    uint32_t keylen;
    int keytype;
    zval *value;
    if (send_header && Z_TYPE_P(send_header) == IS_ARRAY)
    {
        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(send_header), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }

    if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Connection"), (void **) &value) == FAILURE)
    {
        if (http->keep_alive)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        }
        else
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        }
    }

    if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), ZEND_STRL("keep-alive"));
    }

    if (post_data)
    {
        char post_len_str[16];
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            zend_size_t length;
            char *formstr = sw_http_build_query(post_data, &length TSRMLS_CC);
            if (formstr == NULL)
            {
                swoole_php_error(E_WARNING, "http_build_query failed.");
                return SW_ERR;
            }
            swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            swString_append_ptr(http_client_buffer, formstr, length);
        }
        else
        {
            snprintf(post_len_str, sizeof(post_len_str), "%d", Z_STRLEN_P(post_data));
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Length"), post_len_str, strlen(post_len_str));
            swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            swString_append_ptr(http_client_buffer, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data));
        }
    }
    else
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("set_data") TSRMLS_CC);
    zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("set_headers") TSRMLS_CC);

    int ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, (int )http_client_buffer->length);
        zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
    }
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

static http_client* http_client_create(zval *object TSRMLS_DC)
{
    zval *ztmp;
    http_client *http;
    HashTable *vht;

    http = (http_client*) emalloc(sizeof(http_client));
    bzero(http, sizeof(http_client));

    swoole_set_object(object, http);

    php_http_parser_init(&http->parser, PHP_HTTP_RESPONSE);
    http->parser.data = http;

    ztmp = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("host"), 0 TSRMLS_CC);
    http->host = Z_STRVAL_P(ztmp);
    http->host_len = Z_STRLEN_P(ztmp);
    ztmp = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("port"), 0 TSRMLS_CC);
    convert_to_long(ztmp);
    http->port = Z_LVAL_P(ztmp);

    http->timeout = SW_CLIENT_DEFAULT_TIMEOUT;
    http->keep_alive = 0;

    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
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

    http->state = 1;

    return http;
}

static PHP_METHOD(swoole_http_client, __construct)
{
    char *host;
    zend_size_t host_len;
    long port = 80;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &host, &host_len, &port) == FAILURE)
    {
        return;
    }
    
    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len TSRMLS_CC);
    
    zend_update_property_long(swoole_http_client_class_entry_ptr,
    getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    php_swoole_check_reactor();

    //init
    swoole_set_object(getThis(), NULL);

    zval *headers;
    SW_MAKE_STD_ZVAL(headers);
    array_init(headers);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("headers"), headers TSRMLS_CC);

    zval *body;
    SW_MAKE_STD_ZVAL(body);
    SW_ZVAL_STRING(body, "", 1);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("body"), body TSRMLS_CC);

    http_client_callback *hcc;
    hcc = (http_client_callback*) emalloc(sizeof(http_client_callback));
    bzero(hcc, sizeof(http_client_callback));
    swoole_set_property(getThis(), 0, hcc);
    hcc->request_header = headers;

    zval *ztype;
    SW_MAKE_STD_ZVAL(ztype);
    Z_LVAL_P(ztype) = SW_SOCK_TCP | SW_FLAG_ASYNC;
    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), ztype TSRMLS_CC);
    
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, __destruct)
{
    http_client_set_cb(getThis(), ZEND_STRL("finish"), NULL TSRMLS_CC);
    http_client_set_cb(getThis(), ZEND_STRL("close"), NULL TSRMLS_CC);
    http_client_set_cb(getThis(), ZEND_STRL("error"), NULL TSRMLS_CC);
    
    http_client_callback *hcc = swoole_get_property(getThis(), 0);

    if (hcc->request_header)
    {
        sw_zval_ptr_dtor(&hcc->request_header);
    }
    if (hcc->request_body)
    {
        sw_zval_ptr_dtor(&hcc->request_body);
    }

    int i;
    for (i = 0; i < hcc->gc_idx; i++)
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

static PHP_METHOD(swoole_http_client, setHeaders)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("set_headers"), zset TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setData)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("set_data"), zset TSRMLS_CC);
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
        ret = http->cli->close(http->cli);
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

    if (strncasecmp("finish", cb_name, cb_name_len) == 0
        || strncasecmp("error", cb_name, cb_name_len) == 0
        || strncasecmp("close", cb_name, cb_name_len) == 0
        || strncasecmp("message", cb_name, cb_name_len) == 0)
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
// #if PHP_MAJOR_VERSION < 7
//     TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
// #endif
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

    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->cli->object;
    
    zval *headers = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("headers"), 0 TSRMLS_CC);

    char *header_name = zend_str_tolower_dup(http->tmp_header_field_name, http->tmp_header_field_name_len);
    sw_add_assoc_stringl_ex(headers, header_name, http->tmp_header_field_name_len + 1, (char *) at, length, 1);
    //websocket client
    if (strcasecmp(header_name, "Upgrade") == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        http->upgrade = 1;
    }
    efree(header_name);
    return 0;
}

static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->cli->object;
    
    zval *body = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("body"), 0 TSRMLS_CC);
    zval *tmp;
    SW_MAKE_STD_ZVAL(tmp);
    SW_ZVAL_STRINGL(tmp, at, length, 1);
#if PHP_MAJOR_VERSION < 7
    add_string_to_string(body, body, tmp);
#else
    concat_function(body, body, tmp);
#endif
    sw_zval_ptr_dtor(&tmp);

    return 0;
}

static int http_client_parser_on_message_complete(php_http_parser *parser)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->cli->object;

    if (http->keep_alive == 1)
    {
        //reset http phase for reuse
        http->state = HTTP_CLIENT_STATE_READY;
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
    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (http->upgrade)
    {
        http->state = HTTP_CLIENT_STATE_UPGRADE;
        http->buffer =  swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
        if (http->buffer == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            return SW_ERR;
        }
    }
    else if (http->keep_alive == 0)
    {
        http->cli->close(http->cli);
    }

    return 0;
}

static PHP_METHOD(swoole_http_client, execute)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        return;
    }
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, get)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        return;
    }
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, post)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb;
    zval *post_data;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szz", &uri, &uri_len, &post_data, &finish_cb) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "post data must be string or array.");
        RETURN_FALSE;
    }

    http_client_callback *hcc = swoole_get_property(getThis(), 0);
    hcc->request_body = post_data;
    sw_zval_add_ref(&post_data);
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, upgrade)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        return;
    }

    http_client_callback *hcc = swoole_get_property(getThis(), 0);

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    sw_add_assoc_string(hcc->request_header, "Connection", "Upgrade", 1);
    sw_add_assoc_string(hcc->request_header, "Upgrade", "websocket", 1);

    int encoded_value_len = 0;

#if PHP_MAJOR_VERSION < 7
    uchar *encoded_value = php_base64_encode((const unsigned char *)buf, SW_WEBSOCKET_KEY_LENGTH + 1, &encoded_value_len);
#else
    zend_string *str = php_base64_encode((const unsigned char *)buf, SW_WEBSOCKET_KEY_LENGTH + 1);
    char *encoded_value = str->val;
    encoded_value_len = str->len;
#endif

    sw_add_assoc_stringl(hcc->request_header, "Sec-WebSocket-Key", (char*)encoded_value, encoded_value_len, 1);

    ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, push)
{
    char *data;
    zend_size_t length;
    long fd = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &data, &length, &opcode, &fin) == FAILURE)
    {
        return;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swoole_php_fatal_error(E_WARNING, "opcode max 10");
        RETURN_FALSE;
    }

    if (length == 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

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

    if (!http->upgrade)
    {
        swoole_php_fatal_error(E_WARNING, "connection[%d] is not a websocket client.", (int ) fd);
        RETURN_FALSE;
    }

    swString_clear(http_client_buffer);
    swWebSocket_encode(http_client_buffer, data, length, opcode, (int) fin, 0);
    SW_CHECK_RETURN(http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0));
}

#endif
