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
  | Author: Fang  <coooold@live.com>                                     |
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
  +----------------------------------------------------------------------+
*/


#include "php_swoole.h"
#include "thirdparty/php_http_parser.h"

#include "swoole_coroutine.h"
#include <setjmp.h>

#include "ext/standard/basic_functions.h"
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"

#include "websocket.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif


extern swString *swoole_zlib_buffer;

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
    zval *onError;
    zval *onClose;
    zval *onMessage;
    zval *onResponse;


#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _request_body;
    zval _request_header;
    zval _cookies;
    zval _onResponse;
    zval _onConnect;
    zval _onError;
    zval _onClose;
    zval _onMessage;
#endif

    zval *cookies;
    zval *request_header;
    zval *request_body;
    char *request_method;
    int callback_index;

} http_client_property;

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

    swString *buffer;
    swString *body;

    uint8_t state;       //0 wait 1 ready 2 busy
    uint8_t keep_alive;  //0 no 1 keep
    uint8_t upgrade;
    uint8_t gzip;

} http_client;

static int http_client_coro_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_client_coro_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_client_coro_parser_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_client_coro_parser_on_message_complete(php_http_parser *parser);

static void http_client_coro_onReceive(swClient *cli, char *data, uint32_t length);
static void http_client_coro_onConnect(swClient *cli);
static void http_client_coro_onClose(swClient *cli);
static void http_client_coro_onError(swClient *cli);

static int http_client_coro_send_http_request(zval *zobject TSRMLS_DC);
static http_client* http_client_coro_create(zval *object TSRMLS_DC);
static void http_client_free(zval *object TSRMLS_DC);
static int http_client_coro_execute(zval *zobject, char *uri, zend_size_t uri_len TSRMLS_DC);

static void http_client_coro_onTimeout(php_context *cxt);


static sw_inline void http_client_swString_append_headers(swString* swStr, char* key, zend_size_t key_len, char* data, zend_size_t data_len)
{
    swString_append_ptr(swStr, key, key_len);
    swString_append_ptr(swStr, ZEND_STRL(": "));
    swString_append_ptr(swStr, data, data_len);
    swString_append_ptr(swStr, ZEND_STRL("\r\n"));
}

static sw_inline void client_free_php_context(zval *object) {
    //free memory
    php_context *context = swoole_get_property(object, 1);
    if (!context) {
        return;
    }

    efree(context);
    swoole_set_property(object, 1, NULL);
}


static const php_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_client_coro_parser_on_header_field,
    http_client_coro_parser_on_header_value,
    NULL,
    http_client_coro_parser_on_body,
    http_client_coro_parser_on_message_complete
};

zend_class_entry swoole_http_client_coro_ce;
zend_class_entry *swoole_http_client_coro_class_entry_ptr;

static PHP_METHOD(swoole_http_client_coro, __construct);
static PHP_METHOD(swoole_http_client_coro, __destruct);
static PHP_METHOD(swoole_http_client_coro, set);
static PHP_METHOD(swoole_http_client_coro, setMethod);
static PHP_METHOD(swoole_http_client_coro, setHeaders);
static PHP_METHOD(swoole_http_client_coro, setCookies);
static PHP_METHOD(swoole_http_client_coro, setData);
static PHP_METHOD(swoole_http_client_coro, execute);
static PHP_METHOD(swoole_http_client_coro, isConnected);
static PHP_METHOD(swoole_http_client_coro, close);
static PHP_METHOD(swoole_http_client_coro, get);
static PHP_METHOD(swoole_http_client_coro, post);

static const zend_function_entry swoole_http_client_coro_methods[] =
{
    PHP_ME(swoole_http_client_coro, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client_coro, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http_client_coro, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setMethod, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setHeaders, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setCookies, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setData, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, execute, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, get, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, post, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, close, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_client_coro_execute(zval *zobject, char *uri, zend_size_t uri_len TSRMLS_DC)
{
    if (uri_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty.");
        return SW_ERR;
    }

    http_client *http = swoole_get_object(zobject);

    //http is not null when keeping alive
    if (http)
    {
        //http not ready
        if (http->state != HTTP_CLIENT_STATE_READY)
        {
            //swWarn("fd=%d, state=%d, active=%d, keep_alive=%d", http->cli->socket->fd, http->state, http->cli->socket->active, http->keep_alive);
            swoole_php_fatal_error(E_WARNING, "Operation now in progress phase %d.", http->state);
            return SW_ERR;
        }
        else if (!http->cli->socket->active)
        {
            swoole_php_fatal_error(E_WARNING, "connection#%d is closed.", http->cli->socket->fd);
            return SW_ERR;
        }
    }
    else
    {
        http = http_client_coro_create(zobject TSRMLS_CC);
    }

    if (http == NULL)
    {
        return SW_ERR;
    }

    if (http->body == NULL)
    {
        http->body = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
        if (http->body == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            return SW_ERR;
        }
    }
    else
    {
        swString_clear(http->body);
    }

    if (http->uri)
    {
        efree(http->uri);
    }

    http->uri = estrdup(uri);
    http->uri_len = uri_len;
    //if connection exists
    if (http->cli)
    {
        http_client_coro_send_http_request(zobject TSRMLS_CC);

        return SW_OK;
    }


    swClient *cli = php_swoole_client_new(zobject, http->host, http->host_len, http->port);
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
    sw_copy_to_stack(cli->object, hcc->_object);
    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    cli->onReceive = http_client_coro_onReceive;
    cli->onConnect = http_client_coro_onConnect;
    cli->onClose = http_client_coro_onClose;
    cli->onError = http_client_coro_onError;

    return cli->connect(cli, http->host, http->port, http->timeout, 0);

}



static void http_client_coro_onTimeout(php_context *ctx)
{

#if PHP_MAJOR_VERSION < 7
          TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
          zval * zdata;
          zval * retval;
          SW_MAKE_STD_ZVAL(zdata);
          ZVAL_BOOL(zdata, 0); //return false
          zval *zobject = (zval *)ctx->coro_params;
          //define time out RETURN ERROR  110
          zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), 110 TSRMLS_CC);
          http_client_free(zobject TSRMLS_CC);
          swoole_set_object(zobject, NULL);
          if (swoole_multi_resume(zobject, zdata) == CORO_MULTI)
          {
             return;
          }
          int ret = coro_resume(ctx, zdata, &retval);
          if (ret > 0) {
              goto free_zdata;
          }
          if (retval != NULL) {
              sw_zval_ptr_dtor(&retval);
          }
          free_zdata:
          sw_zval_ptr_dtor(&zdata);

}



void swoole_http_client_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_client_coro_ce, "swoole_http_client_coro", "Swoole\\Coroutine\\Http\\Client", swoole_http_client_coro_methods);
    swoole_http_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_http_client_coro_ce TSRMLS_CC);

    swoole_http_client_coro_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_http_client_coro_ce, swoole_client_multi_class_entry_ptr, "swoole_client_multi" TSRMLS_CC);

    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(2048);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

/**
 * @zobject: swoole_http_client_coro object
 */
static void http_client_coro_onClose(swClient *cli)
{
    return;
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_coro_onError(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval * zdata;
    zval * retval;

    SW_MAKE_STD_ZVAL(zdata);
    //return false
    ZVAL_BOOL(zdata, 0);

    zval *zobject = cli->object;
    php_context *sw_current_context = swoole_get_property(zobject, 1);
    zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_DC);
        cli->timeout_id=0;
    }
    if (!cli->released)
    {
        http_client_free(zobject TSRMLS_CC);
    }
    swoole_set_object(zobject, NULL);

    if (swoole_multi_resume(zobject, zdata) == CORO_MULTI)
    {
        return;
    }

    int ret = coro_resume(sw_current_context, zdata, &retval);
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

static void http_client_coro_onReceive(swClient *cli, char *data, uint32_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    zval *retval = NULL;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client_coro.");
        return;
    }
    //timeout
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_DC);
        cli->timeout_id=0;
    }

    long parsed_n = php_http_parser_execute(&http->parser, &http_parser_settings, data, length);
    zval * zdata;
    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 1); //return true
    if (parsed_n < 0)
    {
        zval *retval;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        ZVAL_BOOL(zdata, 0); //return false
    }
    if (swoole_multi_resume(zobject, zdata) == CORO_MULTI)
    {
        return;
    }

    /*if next cr*/
    php_context *sw_current_context = swoole_get_property(zobject, 1);
    int ret = coro_resume(sw_current_context, zdata, &retval);
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


static void http_client_coro_onConnect(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client_coro.");
        return;
    }
    http_client_coro_send_http_request(zobject TSRMLS_CC);
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

static int http_client_coro_send_http_request(zval *zobject TSRMLS_DC)
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

    http_client_property *hcc = swoole_get_property(zobject, 0);

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
    hcc->request_method = NULL;
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));
    swString_append_ptr(http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    char *key;
    uint32_t keylen;
    int keytype;
    zval *value;

    if (send_header && Z_TYPE_P(send_header) == IS_ARRAY)
    {
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
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

#ifdef SW_HAVE_ZLIB
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Accept-Encoding"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
        }
#endif

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(send_header), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        http->keep_alive = 1;
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
#ifdef SW_HAVE_ZLIB
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
#endif
    }

    if (hcc->cookies && Z_TYPE_P(hcc->cookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(hcc->cookies)->nNumOfElements;
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->cookies), key, keylen, keytype, value)
            i ++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            swString_append_ptr(http_client_buffer, key, keylen);
            swString_append_ptr(http_client_buffer, "=", 1);

            int encoded_value_len;
            encoded_value = sw_php_url_encode( Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(http_client_buffer, encoded_value, encoded_value_len);
                efree(encoded_value);
            }
            if (i < n_cookie)
            {
                swString_append_ptr(http_client_buffer, "; ", 2);
            }
        SW_HASHTABLE_FOREACH_END();
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    if (post_data)
    {
        char content_length_str[32];
        int n;

        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            zend_size_t len;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            smart_str formstr_s = { 0 };
            char *formstr = sw_http_build_query(post_data, &len TSRMLS_CC);
            if (formstr == NULL)
            {
                swoole_php_error(E_WARNING, "http_build_query failed.");
                return SW_ERR;
            }
            n = snprintf(content_length_str, sizeof(content_length_str), "Content-Length: %d\r\n\r\n", len);
            swString_append_ptr(http_client_buffer, content_length_str, n);
            swString_append_ptr(http_client_buffer, formstr, len);
            smart_str_free(&formstr_s);
        }
        else
        {
            n = snprintf(content_length_str, sizeof(content_length_str), "Content-Length: %d\r\n\r\n", Z_STRLEN_P(post_data));
            swString_append_ptr(http_client_buffer, content_length_str, n);
            swString_append_ptr(http_client_buffer, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data));
        }

        zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody") TSRMLS_CC);
        hcc->request_body = NULL;
    }
    else
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    swTrace("[%ld]: %s\n", http_client_buffer->length, http_client_buffer->str);

    int ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, (int )http_client_buffer->length);
        zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
    }
    return ret;
}

static http_client* http_client_coro_create(zval *object TSRMLS_DC)
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
            convert_to_double(ztmp);
            http->timeout = (double) Z_DVAL_P(ztmp);
        }
        /**
         * keep_alive
         */
        if (sw_zend_hash_find(vht, ZEND_STRS("keep_alive"), (void **) &ztmp) == SUCCESS)
        {
            convert_to_boolean(ztmp);
            http->keep_alive = (int) Z_LVAL_P(ztmp);
        }
    }

    http->state = HTTP_CLIENT_STATE_READY;

    return http;
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    char *host;
    zend_size_t host_len;
    long port = 80;
    zend_bool ssl = SW_FALSE;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &host, &host_len, &port, &ssl) == FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len TSRMLS_CC);

    zend_update_property_long(swoole_http_client_coro_class_entry_ptr,getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    php_swoole_check_reactor();

    //init
    swoole_set_object(getThis(), NULL);

    zval *headers;
    SW_MAKE_STD_ZVAL(headers);
    array_init(headers);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("headers"), headers TSRMLS_CC);
    sw_zval_ptr_dtor(&headers);

    http_client_property *hcc;
    hcc = (http_client_property*) emalloc(sizeof(http_client_property));
    bzero(hcc, sizeof(http_client_property));
    swoole_set_property(getThis(), 0, hcc);

    int flags = SW_SOCK_TCP | SW_FLAG_ASYNC;
    if (ssl)
    {
        flags |= SW_SOCK_SSL;
    }

    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), flags TSRMLS_CC);

    RETURN_TRUE;
}



static void http_client_free(zval *object TSRMLS_DC)
{
    //todo remove timenode
    http_client *http = swoole_get_object(object);
    if (!http)
    {
        return;
    }

    if (http->uri)
    {
        efree(http->uri);
    }
    if (http->body)
    {
        swString_free(http->body);
    }
    if (http->buffer)
    {
        swString_free(http->buffer);
    }

    swClient *cli = http->cli;
    if (cli)
    {
        php_swoole_client_free(object, cli TSRMLS_CC);
        http->cli = NULL;
    }
    efree(http);
}


static PHP_METHOD(swoole_http_client_coro, __destruct)
{
    //free context
    client_free_php_context(getThis());
    http_client *http = swoole_get_object(getThis());
    if (http)
    {
        zval *zobject = getThis();
        zval *retval;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_client_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    efree(hcc);
    swoole_set_property(getThis(), 0, NULL);
}

static PHP_METHOD(swoole_http_client_coro, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &headers) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), headers TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_header = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_header, hcc->_request_header);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &cookies) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("cookies"), cookies TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->cookies = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("cookies"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->cookies, hcc->_cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setData)
{
    zval *data;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setMethod)
{
    zval *data;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_body = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_body, hcc->_request_body);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, isConnected)
{
    http_client *http = swoole_get_object(getThis());
    if (!http || !http->cli)
    {
        RETURN_FALSE;
    }
    if (!http->cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(http->cli->socket->active);
}

static PHP_METHOD(swoole_http_client_coro, close)
{
    http_client *http = swoole_get_object(getThis());
    if(!http){
        RETURN_TRUE;
    }

    swClient *cli = http->cli;
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        RETURN_FALSE;
    }
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_DC);
        cli->timeout_id=0;
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
    int ret = SW_OK;
    if (!cli->keep || swConnection_error(SwooleG.error) == SW_CLOSE)
    {
        cli->released = 1;
        ret = cli->close(cli);
        http_client_free(getThis() TSRMLS_CC);
    }
    else
    {
        //unset object
        swoole_set_object(getThis(), NULL);
    }
    SW_CHECK_RETURN(ret);
}



static int http_client_coro_parser_on_header_field(php_http_parser *parser, const char *at, size_t length)
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

static int http_client_coro_parser_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->cli->object;
    zval *headers = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("headers"), 0 TSRMLS_CC);

    char *header_name = zend_str_tolower_dup(http->tmp_header_field_name, http->tmp_header_field_name_len);
    sw_add_assoc_stringl_ex(headers, header_name, http->tmp_header_field_name_len + 1, (char *) at, length, 1);
    //websocket client
    if (strcasecmp(header_name, "Upgrade") == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        http->upgrade = 1;
    }
    else if (strcasecmp(header_name, "Set-Cookie") == 0)
    {
        int l_cookie =0;
        if(strchr(at, ';')){
            l_cookie = strchr(at, ';') - at;
        }else{
            l_cookie=strstr(at,"\r\n")-at;
        }
        int l_key = strchr(at, '=') - at;
        char keybuf[SW_HTTP_COOKIE_KEYLEN];

        zval *cookies = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("cookies"), 1 TSRMLS_CC);
        if (!cookies || ZVAL_IS_NULL(cookies))
        {
            SW_MAKE_STD_ZVAL(cookies);
            array_init(cookies);
            zend_update_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("cookies"), cookies TSRMLS_CC);
            sw_zval_ptr_dtor(&cookies);
        }

        memcpy(keybuf, at, l_key);
        keybuf[l_key] = '\0';
        sw_add_assoc_stringl_ex(cookies, keybuf, l_key + 1, (char*) at + l_key + 1, l_cookie - l_key - 1, 1);
    }
#ifdef SW_HAVE_ZLIB
    else if (strcasecmp(header_name, "Content-Encoding") == 0 && strncasecmp(at, "gzip", length) == 0)
    {
        http->gzip = 1;
    }
#endif
    efree(header_name);
    return 0;
}


#ifdef SW_HAVE_ZLIB
static int http_response_uncompress(char *body, int length)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (Z_OK != inflateInit2(&stream, MAX_WBITS + 16))
    {
        swWarn("inflateInit2() failed.");
        return SW_ERR;
    }

    int status = 0;

    stream.avail_in = length;
    stream.next_in = (Bytef *) body;

    swString_clear(swoole_zlib_buffer);

#if 0
    printf(SW_START_LINE"\nstatus=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld\n", status, stream.avail_in, stream.avail_out,
                        stream.total_in, stream.total_out);
#endif

    while (1)
    {
        stream.avail_out = swoole_zlib_buffer->size - stream.total_out;
        stream.next_out = (Bytef *) (swoole_zlib_buffer->str + stream.total_out);

        status = inflate(&stream, Z_SYNC_FLUSH);

#if 0
        printf("status=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld\n", status, stream.avail_in, stream.avail_out,
                stream.total_in, stream.total_out);
#endif

        if (status == Z_STREAM_END)
        {
            swoole_zlib_buffer->length = stream.total_out;
            inflateEnd(&stream);
            return SW_OK;
        }
        else if (status == Z_OK)
        {
            if (stream.total_out >= swoole_zlib_buffer->size)
            {
                swString_extend(swoole_zlib_buffer, swoole_zlib_buffer->size * 2);
            }
        }
        else
        {
            inflateEnd(&stream);
            return SW_ERR;
        }
    }
    return SW_ERR;
}
#endif


static int http_client_coro_parser_on_body(php_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    if (swString_append_ptr(http->body, (char *) at, length) < 0)
    {
        return -1;
    }
    return 0;
}

static int http_client_coro_parser_on_message_complete(php_http_parser *parser)
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

    if (http->gzip)
    {
        if (http_response_uncompress(http->body->str, http->body->length) == SW_ERR)
        {
            swWarn("http_response_uncompress failed.");
            return 0;
        }
        zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("body"), swoole_zlib_buffer->str, swoole_zlib_buffer->length TSRMLS_CC);
    }
    else
    {
        zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("body"), http->body->str, http->body->length TSRMLS_CC);
    }

    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("statusCode"), http->parser.status_code TSRMLS_CC);

    if (http->keep_alive == 0)
    {
        zval *retval;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
     }

    return 0;
}


static PHP_METHOD(swoole_http_client_coro, execute)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if(ret==SW_ERR){
        SW_CHECK_RETURN(ret);
    }


    php_context *context = swoole_get_property(getThis(), 1);
    if (!context) {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 1, context);
    }
    http_client *http = swoole_get_object(getThis());
    context->onTimeout = http_client_coro_onTimeout;
    context->coro_params = getThis();
    context->coro_params_cnt = 1;
    http->cli->timeout_id = php_swoole_add_timer_coro((int)(http->timeout*1000), http->cli->socket->fd, (void *)context);
    if (swoole_multi_is_multi_mode(getThis()) == CORO_MULTI)
    {
        RETURN_TRUE;
    }
    coro_save(return_value, return_value_ptr, context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_method = "GET";
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret==SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }


    http_client *http = swoole_get_object(getThis());
    php_context *context = swoole_get_property(getThis(), 1);
    if (!context)
    {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 1, context);
    }
    context->onTimeout = http_client_coro_onTimeout;
    context->coro_params = getThis();
    context->coro_params_cnt = 1;
    http->cli->timeout_id = php_swoole_add_timer_coro((int)(http->timeout*1000), http->cli->socket->fd, (void *)context);
    if (swoole_multi_is_multi_mode(getThis()) == CORO_MULTI)
    {
        RETURN_TRUE;
    }
    coro_save(return_value, return_value_ptr, context);
    coro_yield();
}


static PHP_METHOD(swoole_http_client_coro, post)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *post_data;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szz", &uri, &uri_len, &post_data) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "post data must be string or array.");
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), post_data TSRMLS_CC);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_body, hcc->_request_body);
    hcc->request_method = "POST";
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret==SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }
      //if multi  no timeout
    if (swoole_multi_is_multi_mode(getThis()) == CORO_MULTI)
    {
        RETURN_TRUE;
    }
    http_client *http = swoole_get_object(getThis());
    php_context *context = swoole_get_property(getThis(), 1);
    if (!context)
    {
        context = emalloc(sizeof(php_context));
        swoole_set_property(getThis(), 1, context);
    }
    context->onTimeout = http_client_coro_onTimeout;
    context->coro_params = getThis();
    context->coro_params_cnt = 1;
    http->cli->timeout_id = php_swoole_add_timer_coro((int)(http->timeout*1000), http->cli->socket->fd, (void *)context);
    if (swoole_multi_is_multi_mode(getThis()) == CORO_MULTI)
    {
        RETURN_TRUE;
    }
    coro_save(return_value, return_value_ptr, context);
    coro_yield();
}
