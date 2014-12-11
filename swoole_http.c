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
#include <ext/standard/url.h>
#include <ext/standard/base64.h>
#include <ext/standard/sha1.h>
#include <ext/date/php_date.h>
#include <main/php_variables.h>
#include <include/swoole.h>
#include <include/websocket.h>
#include <include/Connection.h>

#include "thirdparty/php_http_parser.h"

typedef struct
{
    enum php_http_method method;
    int version;
    char *path;
    uint32_t path_len;
    const char *ext;
    uint32_t ext_len;
    uint8_t post_form_urlencoded;
    char *post_content;
    uint32_t post_length;
} http_request;

typedef struct
{
    enum php_http_method method;
    int version;
    int status;
    swString *cookie;
} http_response;

typedef struct
{
    int fd;
    uint8_t end;

    http_request request;
    http_response response;

    zval *zresponse;
    zval *zrequest;

    php_http_parser parser;
    unsigned int request_read :1;
    char *current_header_name;
    size_t current_header_name_len;
    unsigned int current_header_name_allocated :1;
    unsigned int content_sender_initialized :1;
} http_client;

zend_class_entry swoole_http_server_ce;
zend_class_entry *swoole_http_server_class_entry_ptr;

zend_class_entry swoole_http_response_ce;
zend_class_entry *swoole_http_response_class_entry_ptr;

zend_class_entry swoole_http_request_ce;
zend_class_entry *swoole_http_request_class_entry_ptr;


zend_class_entry swoole_http_wsresponse_ce;
zend_class_entry *swoole_http_wsresponse_class_entry_ptr;

static zval* php_sw_http_server_callbacks[4];
static swHashMap *php_sw_http_clients;

static int http_onReceive(swFactory *factory, swEventData *req);
static void http_onClose(swServer *serv, int fd, int from_id);

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(php_http_parser *parser);
static int http_request_message_complete(php_http_parser *parser);

static void http_client_free(http_client *client);
static void http_request_free(http_client *client TSRMLS_DC);
static http_client* http_client_new(int fd TSRMLS_DC);
static int http_request_new(http_client* c TSRMLS_DC);

static int websocket_handshake(http_client *client);
static void handshake_success(int fd);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    http_request_on_path,
    http_request_on_query_string,
    NULL,
    NULL,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
    http_request_on_body,
    http_request_message_complete
};

const zend_function_entry swoole_http_server_methods[] =
{
    PHP_ME(swoole_http_server, on,         arginfo_swoole_http_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server, start,      NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_request_methods[] =
{
    PHP_ME(swoole_http_request, rawcontent,         NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_response_methods[] =
{
    PHP_ME(swoole_http_response, cookie, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, rawcookie, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, status, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, header, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, end, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


const zend_function_entry swoole_http_wsresponse_methods[] =
{
    PHP_ME(swoole_http_wsresponse, message,         NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length)
{
    http_client *client = parser->data;
    client->request.path = estrndup(at, length);
    client->request.path_len = length;
    return 0;
}

static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_client *client = parser->data;
    char *query = estrndup(at, length);

    zval *get;
    MAKE_STD_ZVAL(get);
    array_init(get);
    zend_update_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("get"), get TSRMLS_CC);
    sapi_module.treat_data(PARSE_STRING, query, get TSRMLS_CC);
    return 0;
}

static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
    http_client *client = parser->data;
    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = (char *)at;
    client->current_header_name_len = length;
    return 0;
}

static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_client *client = parser->data;
    char *header_name = zend_str_tolower_dup(client->current_header_name, client->current_header_name_len);

    if (memcmp(header_name, ZEND_STRL("cookie")) == 0)
    {
        zval *cookie;
        MAKE_STD_ZVAL(cookie);
        array_init(cookie);
        zend_update_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("cookie"), cookie TSRMLS_CC);

        struct
        {
            char *k;
            int klen;
            char *v;
            int vlen;
        } kv = { 0 };

        char keybuf[SW_HTTP_COOKIE_KEYLEN];
        char *_c = (char *) at;
        int n = 1;
        kv.k = _c;

        while (_c < at + length)
        {
            if (*_c == '=')
            {
                kv.v = _c + 1;
                kv.klen = n;
                n = 0;
            }
            else if (*_c == ';')
            {
                kv.vlen = n;
                if (kv.klen >= SW_HTTP_COOKIE_KEYLEN)
                {
                    kv.klen = SW_HTTP_COOKIE_KEYLEN - 1;
                }
                memcpy(keybuf, kv.k, kv.klen - 1);
                keybuf[kv.klen - 1] = 0;
                add_assoc_stringl_ex(cookie, keybuf, kv.klen, kv.v, kv.vlen, 1);
                kv.k = _c + 2;
                n = 0;
            }
            else
            {
                n++;
            }
            _c++;
        }
        kv.vlen = n;
        if (kv.klen >= SW_HTTP_COOKIE_KEYLEN)
        {
            kv.klen = SW_HTTP_COOKIE_KEYLEN - 1;
        }
        memcpy(keybuf, kv.k, kv.klen - 1);
        keybuf[kv.klen - 1] = 0;
        add_assoc_stringl_ex(cookie, keybuf, kv.klen , kv.v, kv.vlen, 1);
    }
    else if (memcmp(header_name, ZEND_STRL("upgrade")) == 0
            && memcmp(at, ZEND_STRL("websocket")) == 0)
    {
        SwooleG.lock.lock(&SwooleG.lock);
        swConnection *conn = swServer_connection_get(SwooleG.serv, client->fd);
        if(conn->websocket_status == 0) {
            conn->websocket_status = WEBSOCKET_STATUS_CONNECTION;
        }
        SwooleG.lock.unlock(&SwooleG.lock);
        zval *header = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
        add_assoc_stringl_ex(header, header_name, client->current_header_name_len + 1, (char *) at, length, 1);
    }
    else if (parser->method == PHP_HTTP_POST && memcmp(header_name, ZEND_STRL("content-type")) == 0
            && memcmp(at, ZEND_STRL("application/x-www-form-urlencoded")) == 0)
    {
        client->request.post_form_urlencoded = 1;
        zval *header = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
        add_assoc_stringl_ex(header, header_name, client->current_header_name_len + 1, (char *) at, length, 1);
    }

    else
    {
        zval *header = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
        add_assoc_stringl_ex(header, header_name, client->current_header_name_len + 1, (char *) at, length, 1);
    }

    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    efree(header_name);
    return 0;
}

static int http_request_on_headers_complete(php_http_parser *parser)
{
    http_client *client = parser->data;
    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = NULL;
    return 0;
}

static int http_request_on_body(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_client *client = parser->data;
    char *body = estrndup(at, length);

    if (client->request.post_form_urlencoded)
    {
        zval *post;
        MAKE_STD_ZVAL(post);
        array_init(post);
        zend_update_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("post"), post TSRMLS_CC);
        sapi_module.treat_data(PARSE_STRING, body, post TSRMLS_CC);
    }
    else
    {
        client->request.post_content = body;
        client->request.post_length = length;
    }

    return 0;
}

static int http_request_message_complete(php_http_parser *parser)
{
    http_client *client = parser->data;
    client->request.version = parser->http_major * 100 + parser->http_minor;

    const char *vpath = client->request.path, *end = vpath + client->request.path_len, *p = end;
    client->request.ext = end;
    client->request.ext_len = 0;
    while (p > vpath)
    {
        --p;
        if (*p == '.')
        {
            ++p;
            client->request.ext = p;
            client->request.ext_len = end - p;
            break;
        }
    }
    client->request_read = 1;
    return 0;
}

static void http_onClose(swServer *serv, int fd, int from_id)
{
    swHashMap_del_int(php_sw_http_clients, fd);

    if (php_sw_callback[SW_SERVER_CB_onClose] != NULL)
    {
        php_swoole_onClose(serv, fd, from_id);
    }
}

static void sha1(const char *str, unsigned char *digest)
{
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *)str, strlen(str));
    PHP_SHA1Final(digest, &context);
    return;
}

static int websocket_handshake(http_client *client)
{

    //HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Version: %s\r\nKeepAlive: off\r\nContent-Length: 0\r\nServer: ZWebSocket\r\n
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    zval *header = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
    HashTable *ht = Z_ARRVAL_P(header);
    zval **pData;
    if(zend_hash_find(ht, ZEND_STRS("sec-websocket-key") , (void **) &pData) == FAILURE) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "header no sec-websocket-key");
        return SW_ERR;
    }
    convert_to_string(*pData);
    swTrace("key: %s len:%d\n", Z_STRVAL_PP(pData), Z_STRLEN_PP(pData));
    swString *buf = swString_new(256);
    swString_append_ptr(buf, ZEND_STRL("HTTP/1.1 101 Switching Protocols\r\n"));
    swString_append_ptr(buf, ZEND_STRL("Upgrade: websocket\r\nConnection: Upgrade\r\n"));
    swString *shaBuf = swString_new(Z_STRLEN_PP(pData)+36);
    swString_append_ptr(shaBuf, Z_STRVAL_PP(pData), Z_STRLEN_PP(pData));
    swString_append_ptr(shaBuf, ZEND_STRL(SW_WEBSOCKET_GUID));

    char data_str[20];
    sha1(shaBuf->str, (unsigned char*) data_str);

    unsigned char *encoded_value = NULL;
    int encoded_len;
    encoded_value = php_base64_encode((unsigned char*) data_str, sizeof(data_str), &encoded_len);
    char _buf[128];
    int n = 0;
    n = snprintf(_buf, 128, "Sec-WebSocket-Accept: %s\r\n", encoded_value);
    //efree(data_str);

    efree(encoded_value);
    swString_free(shaBuf);
    swTrace("accept value: %s\n", _buf);
    swString_append_ptr(buf, _buf, n);
    swString_append_ptr(buf, ZEND_STRL("Sec-WebSocket-Version: 13\r\n"));
    swString_append_ptr(buf, ZEND_STRL("Server: swoole-websocket\r\n\r\n"));
    swTrace("websocket header len:%zd\n%s \n", buf->length, buf->str);

    int ret = swServer_tcp_send(SwooleG.serv, client->fd, buf->str, buf->length);
    swString_free(buf);
    swTrace("handshake send: %d lenght: %d\n", client->fd, ret);
    return ret;
}

static void handshake_success(int fd)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    SwooleG.lock.lock(&SwooleG.lock);
    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION) {
        conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
    }
    SwooleG.lock.unlock(&SwooleG.lock);
    swTrace("\n\n\n\nconn ws status:%d\n\n\n", conn->websocket_status);

    if (php_sw_http_server_callbacks[3] != NULL)
    {
        swTrace("\n\n\n\nhandshake success\n\n\n");
        zval *zresponse;
        MAKE_STD_ZVAL(zresponse);
        object_init_ex(zresponse, swoole_http_wsresponse_class_entry_ptr);
        //socket fd
        zend_update_property_long(swoole_http_wsresponse_class_entry_ptr, zresponse, ZEND_STRL("fd"), fd TSRMLS_CC);

        zval **args[1];
        args[0] = &zresponse;
        zval *retval;

        if (call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[3], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
        }
        swTrace("===== message callback end======");
        if (EG(exception)) {
            zend_exception_error(EG(exception), E_ERROR
            TSRMLS_CC);
        }
        if (retval) {
            zval_ptr_dtor(&retval);
        }
    }
}

static int http_onReceive(swFactory *factory, swEventData *req)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    int fd = req->info.fd;


//    swTrace("on receive:%s pid:%d\n", zdata, getpid());
    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);

    if(conn->websocket_status == WEBSOCKET_STATUS_HANDSHAKE)  //websocket callback
    {
        zval *zdata = php_swoole_get_data(req TSRMLS_CC);
        swTrace("on message callback\n");
        char *buf = Z_STRVAL_P(zdata);
        long fin = buf[0] ? 1 : 0;
        long opcode = buf[1] ? 1 : 0;
        buf+=2;
        zval *zresponse;
        MAKE_STD_ZVAL(zresponse);
        object_init_ex(zresponse, swoole_http_wsresponse_class_entry_ptr);
        //socket fd
        zend_update_property_long(swoole_http_wsresponse_class_entry_ptr, zresponse, ZEND_STRL("fd"), fd TSRMLS_CC);
        zend_update_property_long(swoole_http_wsresponse_class_entry_ptr, zresponse, ZEND_STRL("fin"), fin TSRMLS_CC);
        zend_update_property_long(swoole_http_wsresponse_class_entry_ptr, zresponse, ZEND_STRL("opcode"), opcode TSRMLS_CC);
        zend_update_property_stringl(swoole_http_wsresponse_class_entry_ptr, zresponse, ZEND_STRL("data"), buf, (Z_STRLEN_P(zdata)-2) TSRMLS_CC);

        zval **args[1];
        args[0] = &zresponse;
        zval *retval;
        if (call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[1], &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            zval_ptr_dtor(&zdata);
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
        }
        swTrace("===== message callback end======");
        if (EG(exception))
        {
            zval_ptr_dtor(&zdata);
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            zval_ptr_dtor(&retval);
        }
        zval_ptr_dtor(&zdata);
        return SW_OK;
    }

    http_client *client = swHashMap_find_int(php_sw_http_clients, fd);



    if (!client)
    {
        client = http_client_new(fd TSRMLS_CC);
    }


    php_http_parser *parser = &client->parser;

    /**
     * create request and response object
     */
    http_request_new(client TSRMLS_CC);

    parser->data = client;
    php_http_parser_init(parser, PHP_HTTP_REQUEST);



    zval *zdata = php_swoole_get_data(req TSRMLS_CC);
    size_t n = php_http_parser_execute(parser, &http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    zval_ptr_dtor(&zdata);
    if (n < 0)
    {
        swWarn("php_http_parser_execute failed.");
        if(conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
        }

    }
    else
    {
        if(conn->websocket_status == WEBSOCKET_STATUS_CONNECTION) // need handshake
        {
            if(php_sw_http_server_callbacks[2] == NULL) {
                int ret = websocket_handshake(client);
                http_request_free(client TSRMLS_CC);
                if (ret == SW_ERR) {
                    swTrace("websocket handshake error\n");
                    SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
                } else {
                    handshake_success(fd);
                    return SW_OK;
                }
                return ret;
            }
        }

        zval *retval;
        zval **args[2];
        zval *zrequest = client->zrequest;

    	//server info
    	zval *zserver;
    	MAKE_STD_ZVAL(zserver);
    	array_init(zserver);
    	zend_update_property(swoole_http_request_class_entry_ptr, zrequest, ZEND_STRL("server"), zserver TSRMLS_CC);

        switch (parser->method) {
            case PHP_HTTP_GET: add_assoc_string(zserver, "request_method", "GET", 1);break;
            case PHP_HTTP_POST: add_assoc_string(zserver, "request_method", "POST", 1);break;
            case PHP_HTTP_HEAD: add_assoc_string(zserver, "request_method", "HEAD", 1);break;
            case PHP_HTTP_PUT: add_assoc_string(zserver, "request_method", "PUT", 1);break;
            case PHP_HTTP_DELETE: add_assoc_string(zserver, "request_method", "DELETE", 1);break;
            case PHP_HTTP_PATCH: add_assoc_string(zserver, "request_method", "PATCH", 1);break;
                /* pathological */
            case PHP_HTTP_CONNECT: add_assoc_string(zserver, "request_method", "CONNECT", 1);break;
            case PHP_HTTP_OPTIONS: add_assoc_string(zserver, "request_method", "OPTIONS", 1);break;
            case PHP_HTTP_TRACE: add_assoc_string(zserver, "request_method", "TRACE", 1);break;
                /* webdav */
            case PHP_HTTP_COPY: add_assoc_string(zserver, "request_method", "COPY", 1);break;
            case PHP_HTTP_LOCK: add_assoc_string(zserver, "request_method", "LOCK", 1);break;
            case PHP_HTTP_MKCOL: add_assoc_string(zserver, "request_method", "MKCOL", 1);break;
            case PHP_HTTP_MOVE: add_assoc_string(zserver, "request_method", "MOVE", 1);break;
            case PHP_HTTP_PROPFIND: add_assoc_string(zserver, "request_method", "PROPFIND", 1);break;
            case PHP_HTTP_PROPPATCH: add_assoc_string(zserver, "request_method", "PROPPATCH", 1);break;
            case PHP_HTTP_UNLOCK: add_assoc_string(zserver, "request_method", "UNLOCK", 1);break;
                /* subversion */
            case PHP_HTTP_REPORT: add_assoc_string(zserver, "request_method", "REPORT", 1);break;
            case PHP_HTTP_MKACTIVITY: add_assoc_string(zserver, "request_method", "MKACTIVITY", 1);break;
            case PHP_HTTP_CHECKOUT: add_assoc_string(zserver, "request_method", "CHECKOUT", 1);break;
            case PHP_HTTP_MERGE: add_assoc_string(zserver, "request_method", "MERGE", 1);break;
                /* upnp */
            case PHP_HTTP_MSEARCH: add_assoc_string(zserver, "request_method", "MSEARCH", 1);break;
            case PHP_HTTP_NOTIFY: add_assoc_string(zserver, "request_method", "NOTIFY", 1);break;
            case PHP_HTTP_SUBSCRIBE: add_assoc_string(zserver, "request_method", "SUBSCRIBE", 1);break;
            case PHP_HTTP_UNSUBSCRIBE: add_assoc_string(zserver, "request_method", "UNSUBSCRIBE", 1);break;
            case PHP_HTTP_NOT_IMPLEMENTED: add_assoc_string(zserver, "request_method", "GET", 1);break;
        }

//    	if (parser->method == PHP_HTTP_POST)
//    	{
//    		add_assoc_string(zserver, "request_method", "POST", 1);
//    	}
//    	else
//    	{
//    		add_assoc_string(zserver, "request_method", "GET", 1);
//    	}

    	add_assoc_stringl(zserver, "request_uri", client->request.path, client->request.path_len, 1);
    	add_assoc_stringl(zserver, "path_info", client->request.path, client->request.path_len, 1);
    	add_assoc_long_ex(zserver,  ZEND_STRS("request_time"), SwooleGS->now);

    	swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    	add_assoc_long(zserver, "server_port", SwooleG.serv->connection_list[conn->from_fd].addr.sin_port);
    	add_assoc_long(zserver, "remote_port", ntohs(conn->addr.sin_port));
    	add_assoc_string(zserver, "remote_addr", inet_ntoa(conn->addr.sin_addr), 1);

    	if (client->request.version == 101)
    	{
    		add_assoc_string(zserver, "server_protocol", "HTTP/1.1", 1);
    	}
    	else
    	{
            add_assoc_string(zserver, "server_protocol", "HTTP/1.0", 1);
        }
        add_assoc_string(zserver, "server_software", SW_HTTP_SERVER_SOFTWARE, 1);
        add_assoc_string(zserver, "gateway_interface", SW_HTTP_SERVER_SOFTWARE, 1);

    	zval *zresponse;
    	MAKE_STD_ZVAL(zresponse);
    	object_init_ex(zresponse, swoole_http_response_class_entry_ptr);

    	//socket fd
    	zend_update_property_long(swoole_http_response_class_entry_ptr, zresponse, ZEND_STRL("fd"), client->fd TSRMLS_CC);
    	client->zresponse = zresponse;

        args[0] = &zrequest;
        args[1] = &zresponse;

        int called = 0;
        if(conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            called = 2;
        }
        if (call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[called], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onRequest handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            zval_ptr_dtor(&retval);
        }
        swTrace("======call end======\n");
        if(called == 2) {
            handshake_success(fd);
        }
    }
    return SW_OK;
}

void swoole_http_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http_server_ce, "swoole_http_server", swoole_http_server_methods);
    swoole_http_server_class_entry_ptr = zend_register_internal_class_ex(&swoole_http_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_response_ce, "swoole_http_response", swoole_http_response_methods);
    swoole_http_response_class_entry_ptr = zend_register_internal_class(&swoole_http_response_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_request_ce, "swoole_http_request", swoole_http_request_methods);
    swoole_http_request_class_entry_ptr = zend_register_internal_class(&swoole_http_request_ce TSRMLS_CC);
    
    INIT_CLASS_ENTRY(swoole_http_wsresponse_ce, "swoole_http_wsresponse", swoole_http_wsresponse_methods);
    swoole_http_wsresponse_class_entry_ptr = zend_register_internal_class(&swoole_http_wsresponse_ce TSRMLS_CC);
}

PHP_METHOD(swoole_http_server, on)
{
    zval *callback;
    zval *event_name;
    swServer *serv;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &event_name, &callback) == FAILURE)
    {
        return;
    }

    SWOOLE_GET_SERVER(getThis(), serv);

    char *func_name = NULL;
    if (!zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    if (strncasecmp("request", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[0] = callback;
    }
    else if (strncasecmp("message", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[1] = callback;
    }
    else if (strncasecmp("handshake", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[2] = callback;
    }
    else if (strncasecmp("open", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[3] = callback;
    }
    else
    {
        zend_call_method_with_2_params(&getThis(), swoole_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}

static void http_client_free(http_client *client)
{
    if (client->zrequest)
    {
        TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
        http_request_free(client TSRMLS_CC);
    }
    efree(client);
}

static http_client* http_client_new(int fd TSRMLS_DC)
{
    http_client *client = emalloc(sizeof(http_client));
    bzero(client, sizeof(http_client));
    client->fd = fd;
    swHashMap_add_int(php_sw_http_clients, fd, client, NULL);
    return client;
}

static int http_request_new(http_client* client TSRMLS_DC)
{
	zval *zrequest;
	MAKE_STD_ZVAL(zrequest);
	object_init_ex(zrequest, swoole_http_request_class_entry_ptr);

	//http header
	zval *header;
	MAKE_STD_ZVAL(header);
	array_init(header);
	zend_update_property(swoole_http_request_class_entry_ptr, zrequest, ZEND_STRL("header"), header TSRMLS_CC);

	client->zrequest = zrequest;
	client->end = 0;

	zend_update_property_long(swoole_http_request_class_entry_ptr, zrequest, ZEND_STRL("fd"), client->fd TSRMLS_CC);

	bzero(&client->request, sizeof(client->request));
	bzero(&client->response, sizeof(client->response));

	return SW_OK;
}

static void http_request_free(http_client *client TSRMLS_DC)
{
    http_request *req = &client->request;
    if (req->path)
    {
        efree(req->path);
    }
    if (req->post_content)
    {
        efree(req->post_content);
    }
    http_response *resp = &client->response;
    if (resp->cookie)
    {
        swString_free(resp->cookie);
    }
    /**
     * Free request object
     */
    zval *zheader = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zheader))
    {
        zval_ptr_dtor(&zheader);
    }
    zval *zget = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("get"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zget))
    {
        zval_ptr_dtor(&zget);
    }
    zval *zpost = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("post"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zpost))
    {
        zval_ptr_dtor(&zpost);
    }
    zval *zserver = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("server"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zserver))
    {
        zval_ptr_dtor(&zserver);
    }
    zval_ptr_dtor(&client->zrequest);
    client->zrequest = NULL;
    if(client->zresponse) {
        zval_ptr_dtor(&client->zresponse);
        client->zresponse = NULL;
    }
    client->end = 1;
}

static char *http_status_message(int code)
{
    switch (code)
    {
    case 100:
        return "100 Continue";
    case 101:
        return "101 Switching Protocols";
    case 201:
        return "201 Created";
    case 204:
        return "204 No Content";
    case 206:
        return "206 Partial Content";
    case 300:
        return "300 Multiple Choices";
    case 301:
        return "301 Moved Permanently";
    case 302:
        return "302 Found";
    case 303:
        return "303 See Other";
    case 304:
        return "304 Not Modified";
    case 307:
        return "307 Temporary Redirect";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 405:
        return "405 Method Not Allowed";
    case 406:
        return "406 Not Acceptable";
    case 408:
        return "408 Request Timeout";
    case 410:
        return "410 Gone";
    case 413:
        return "413 Request Entity Too Large";
    case 414:
        return "414 Request URI Too Long";
    case 415:
        return "415 Unsupported Media Type";
    case 416:
        return "416 Requested Range Not Satisfiable";
    case 417:
        return "417 Expectation Failed";
    case 500:
        return "500 Internal Server Error";
    case 501:
        return "501 Method Not Implemented";
    case 503:
        return "503 Service Unavailable";
    case 506:
        return "506 Variant Also Negotiates";
    case 200:
    default:
        return "200 OK";
    }
}

PHP_METHOD(swoole_http_server, start)
{
    swServer *serv;
    int ret;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    SWOOLE_GET_SERVER(getThis(), serv);
    php_swoole_register_callback(serv);

    if (php_sw_http_server_callbacks[0] == NULL && php_sw_http_server_callbacks[1] == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onRequest or onMessage callback");
        RETURN_FALSE;
    }

    serv->dispatch_mode = SW_DISPATCH_FDMOD;
    serv->onReceive = http_onReceive;
    serv->onClose = http_onClose;
    serv->open_http_protocol = 1;

    serv->ptr2 = getThis();

    php_sw_http_clients = swHashMap_new(1024, (void (*)(void *)) http_client_free);

    ret = swServer_create(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "create server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    zend_update_property_long(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("master_pid"), getpid() TSRMLS_CC);
    ret = swServer_start(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "start server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_http_request, rawcontent)
{
    zval *zfd = zend_read_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    if (ZVAL_IS_NULL(zfd))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client not exists.");
        RETURN_FALSE;
    }
    http_client *client = swHashMap_find_int(php_sw_http_clients, Z_LVAL_P(zfd));
    if (!client)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client[#%d] not exists.", (int) Z_LVAL_P(zfd));
        RETURN_FALSE;
    }
    if (!client->request.post_content)
    {
        RETURN_FALSE;
    }
    RETVAL_STRINGL(client->request.post_content, client->request.post_length, 0);
    client->request.post_content = NULL;
}

PHP_METHOD(swoole_http_response, end)
{
    swString body;
    body.length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &body.str, &body.length) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    if (ZVAL_IS_NULL(zfd))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client not exists.");
        RETURN_FALSE;
    }

    http_client *client = swHashMap_find_int(php_sw_http_clients, Z_LVAL_P(zfd));
    if (!client)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client[#%d] not exists.", (int) Z_LVAL_P(zfd));
        RETURN_FALSE;
    }

    if (client->end)
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Response is end.");
		RETURN_FALSE;
	}

    char buf[128];
    int n;

    int keepalive = php_http_should_keep_alive(&client->parser);
    swString *response = swString_new(body.length + 1024);
    char *date_str;

    /**
     * Http status line
     */
    n = snprintf(buf, 128, "HTTP/1.1 %s\r\n", http_status_message(client->response.status));
    swString_append_ptr(response, buf, n);

    /**
     * Http header
     */
    zval *header =  zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("header"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(header))
    {
        int flag = 0x0;
        char *key_server = "Server";
        char *key_connection = "Connection";
        char *key_content_length = "Content-Length";
        char *key_date = "Date";
        HashTable *ht = Z_ARRVAL_P(header);
        for (zend_hash_internal_pointer_reset(ht); zend_hash_has_more_elements(ht) == 0; zend_hash_move_forward(ht))
        {
            char *key;
            uint keylen;
            ulong idx;
            int type;
            zval **value;

            type = zend_hash_get_current_key_ex(ht, &key, &keylen, &idx, 0, NULL);
            if (type == HASH_KEY_IS_LONG || zend_hash_get_current_data(ht, (void**)&value) == FAILURE)
            {
                continue;
            }
            if(strcmp(key, key_server) == 0) 
            {
                flag |= 0x1;
            }
            else if(strcmp(key, key_connection) == 0) 
            {
                flag |= 0x2;
            }
            else if(strcmp(key, key_content_length) == 0) 
            {
                flag |= 0x4;
            }
            else if(strcmp(key, key_date) == 0) 
            {
                flag |= 0x8;
            }
            n = snprintf(buf, 128, "%s: %s\r\n", key, Z_STRVAL_PP(value));
            swString_append_ptr(response, buf, n);
        }
        
        if (!(flag & 0x1))
        {
            swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\n"));
        }
        if (!(flag & 0x2))
        {
            if (keepalive)
            {
                swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
            }
            else
            {
                swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
            }
        }

        if(client->request.method == PHP_HTTP_OPTIONS)
        {
            swString_append_ptr(response, ZEND_STRL("Allow: GET, POST, PUT, DELETE, HEAD, OPTIONS\r\nContent-Length: 0\r\n"));
        }
        else
        {
            if (!(flag & 0x4))
            {
                n = snprintf(buf, 128, "Content-Length: %d\r\n", body.length);
                swString_append_ptr(response, buf, n);
            }
        }


        if (!(flag & 0x8))
        {
            date_str = php_format_date(ZEND_STRL("D, d-M-Y H:i:s T"), SwooleGS->now, 0 TSRMLS_CC);
            n = snprintf(buf, 128, "Date: %s\r\n", date_str);
            swString_append_ptr(response, buf, n);
            efree(date_str);
        }
    }
    else
    {
        swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\n"));
        if (keepalive)
        {
            swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
        }
        else
        {
            swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
        }

        date_str = php_format_date(ZEND_STRL("D, d-M-Y H:i:s T"), 1, SwooleGS->now TSRMLS_CC);
        n = snprintf(buf, 128, "Date: %s\r\n", date_str);
        efree(date_str);
        swString_append_ptr(response, buf, n);
        if(client->request.method == PHP_HTTP_OPTIONS) {
            n = snprintf(buf, 128, "Allow: GET, POST, PUT, DELETE, HEAD, OPTIONS\r\nContent-Length: %d\r\n", 0);
        } else {
            n = snprintf(buf, 128, "Content-Length: %d\r\n", body.length);
        }
        swString_append_ptr(response, buf, n);
    }

    if (client->response.cookie)
    {
        swString_append(response, client->response.cookie);
    }

    swString_append_ptr(response, ZEND_STRL("\r\n"));

    if(client->request.method != PHP_HTTP_HEAD)  {
        swString_append(response, &body);
    }

    int ret = swServer_tcp_send(SwooleG.serv, Z_LVAL_P(zfd), response->str, response->length);

    swString_free(response);
    http_request_free(client TSRMLS_CC);

    if (!keepalive)
    {
        SwooleG.serv->factory.end(&SwooleG.serv->factory, Z_LVAL_P(zfd));
    }
    SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_http_response, cookie)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    long expires = 0;
    int encode = 1;
    zend_bool secure = 0, httponly = 0;
    int name_len, value_len = 0, path_len = 0, domain_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|slssbb", &name, &name_len, &value, &value_len, &expires,
                &path, &path_len, &domain, &domain_len, &secure, &httponly) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    if (ZVAL_IS_NULL(zfd))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client not exists.");
        RETURN_FALSE;
    }

    http_client *client = swHashMap_find_int(php_sw_http_clients, Z_LVAL_P(zfd));
    if (!client)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client[#%d] not exists.", (int) Z_LVAL_P(zfd));
        RETURN_FALSE;
    }

    if (client->end)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Response is end.");
        RETURN_FALSE;
    }

    char *cookie, *encoded_value = NULL;
    int len = sizeof("Set-Cookie: ");
    char *dt;

    if (name && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Cookie names cannot contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    if (!client->response.cookie)
    {
        client->response.cookie = swString_new(1024);
    }

    len += name_len;
    if (encode && value)
    {
        int encoded_value_len;
        encoded_value = php_url_encode(value, value_len, &encoded_value_len);
        len += encoded_value_len;
    }
    else if (value)
    {
        encoded_value = estrdup(value);
        len += value_len;
    }
    if (path)
    {
        len += path_len;
    }
    if (domain)
    {
        len += domain_len;
    }

    cookie = emalloc(len + 100);

    if (value && value_len == 0)
    {
        dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, 1, 0 TSRMLS_CC);
        snprintf(cookie, len + 100, "Set-Cookie: %s=deleted; expires=%s", name, dt);
        efree(dt);
    }
    else
    {
        snprintf(cookie, len + 100, "Set-Cookie: %s=%s", name, value ? encoded_value : "");
        if (expires > 0)
        {
            const char *p;
            strlcat(cookie, "; expires=", len + 100);
            dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, expires, 0 TSRMLS_CC);
            p = zend_memrchr(dt, '-', strlen(dt));
            if (!p || *(p + 5) != ' ')
            {
                efree(dt);
                efree(cookie);
                efree(encoded_value);
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Expiry date cannot have a year greater than 9999");
                RETURN_FALSE;
            }
            strlcat(cookie, dt, len + 100);
            efree(dt);
        }
    }
    if (encoded_value)
    {
        efree(encoded_value);
    }
    if (path && path_len > 0)
    {
        strlcat(cookie, "; path=", len + 100);
        strlcat(cookie, path, len + 100);
    }
    if (domain && domain_len > 0)
    {
        strlcat(cookie, "; domain=", len + 100);
        strlcat(cookie, domain, len + 100);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", len + 100);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", len + 100);
    }
    swString_append_ptr(client->response.cookie, cookie, strlen(cookie));
    swString_append_ptr(client->response.cookie, ZEND_STRL("\r\n"));
    efree(cookie);
}

PHP_METHOD(swoole_http_response, rawcookie)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    long expires = 0;
    int encode = 0;
    zend_bool secure = 0, httponly = 0;
    int name_len, value_len = 0, path_len = 0, domain_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|slssbb", &name, &name_len, &value, &value_len, &expires,
                &path, &path_len, &domain, &domain_len, &secure, &httponly) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    if (ZVAL_IS_NULL(zfd))
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client not exists.");
        RETURN_FALSE;
    }

    http_client *client = swHashMap_find_int(php_sw_http_clients, Z_LVAL_P(zfd));
    if (!client)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client[#%d] not exists.", (int) Z_LVAL_P(zfd));
        RETURN_FALSE;
    }

    if (client->end)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Response is end.");
        RETURN_FALSE;
    }

    char *cookie, *encoded_value = NULL;
    int len = sizeof("Set-Cookie: ");
    char *dt;

    if (name && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Cookie names cannot contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    if (!client->response.cookie)
    {
        client->response.cookie = swString_new(1024);
    }

    len += name_len;
    if (encode && value)
    {
        int encoded_value_len;
        encoded_value = php_url_encode(value, value_len, &encoded_value_len);
        len += encoded_value_len;
    }
    else if (value)
    {
        encoded_value = estrdup(value);
        len += value_len;
    }
    if (path)
    {
        len += path_len;
    }
    if (domain)
    {
        len += domain_len;
    }

    cookie = emalloc(len + 100);

    if (value && value_len == 0)
    {
        dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, 1, 0 TSRMLS_CC);
        snprintf(cookie, len + 100, "Set-Cookie: %s=deleted; expires=%s", name, dt);
        efree(dt);
    }
    else
    {
        snprintf(cookie, len + 100, "Set-Cookie: %s=%s", name, value ? encoded_value : "");
        if (expires > 0)
        {
            const char *p;
            strlcat(cookie, "; expires=", len + 100);
            dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, expires, 0 TSRMLS_CC);
            p = zend_memrchr(dt, '-', strlen(dt));
            if (!p || *(p + 5) != ' ')
            {
                efree(dt);
                efree(cookie);
                efree(encoded_value);
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "Expiry date cannot have a year greater than 9999");
                RETURN_FALSE;
            }
            strlcat(cookie, dt, len + 100);
            efree(dt);
        }
    }
    if (encoded_value)
    {
        efree(encoded_value);
    }
    if (path && path_len > 0)
    {
        strlcat(cookie, "; path=", len + 100);
        strlcat(cookie, path, len + 100);
    }
    if (domain && domain_len > 0)
    {
        strlcat(cookie, "; domain=", len + 100);
        strlcat(cookie, domain, len + 100);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", len + 100);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", len + 100);
    }
    swString_append_ptr(client->response.cookie, cookie, strlen(cookie));
    swString_append_ptr(client->response.cookie, ZEND_STRL("\r\n"));
    efree(cookie);
}

PHP_METHOD(swoole_http_response, status)
{
    long http_status;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &http_status) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    http_client *client = swHashMap_find_int(php_sw_http_clients, Z_LVAL_P(zfd));

    client->response.status = http_status;
}

PHP_METHOD(swoole_http_response, header)
{
    char *k, *v;
    int klen, vlen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &k, &klen, &v, &vlen) == FAILURE)
    {
        return;
    }
    zval *header = zend_read_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("header"), 1 TSRMLS_CC);
    if (!header || ZVAL_IS_NULL(header))
    {
        MAKE_STD_ZVAL(header);
        array_init(header);
        zend_update_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("header"), header TSRMLS_CC);
    }
    add_assoc_stringl_ex(header, k, klen + 1, v, vlen, 1);
}

/**
 * For websocket send message
 */
PHP_METHOD(swoole_http_wsresponse, message)
{
    swString data;
    data.length = 0;
    long fd = 0;
    long opcode = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &data.str, &data.length, &fd, &opcode) == FAILURE)
    {
        return;
    }

    if(fd == 0)
    {
        zval *zfd = zend_read_property(swoole_http_wsresponse_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
        if (ZVAL_IS_NULL(zfd))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "http client not exists.");
            RETURN_FALSE;
        }
        fd = Z_LVAL_P(zfd);
    }

    char _opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    switch(opcode) {
        case 2:
            _opcode = WEBSOCKET_OPCODE_BINARY_FRAME;
            break;
    }

    swTrace("need send:%s len:%zd\n", data.str, data.length);
    swString *response = swWebSocket_encode(&data, _opcode);
    int ret = swServer_tcp_send(SwooleG.serv, fd, response->str, response->length);
    swTrace("need send:%s len:%zd\n", response->str, response->length);
    swString_free(response);
    SW_CHECK_RETURN(ret);
}

