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
#include <ext/standard/sha1.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_string.h>
#include <ext/date/php_date.h>

#include <main/php_variables.h>

#include "websocket.h"
#include "Connection.h"
#include "base64.h"
/*******/
#include "mylib/base64.h"
#include "mylib/intLib.h"
#include "mylib/sha1.h"

#include "thirdparty/php_http_parser.h"


static swArray *websocket_client_array;

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
    int fd;
    uint8_t end;
    http_request request;

    zval *zrequest;

	php_http_parser parser;
    unsigned int request_read :1;
    char *current_header_name;
    size_t current_header_name_len;
    unsigned int current_header_name_allocated :1;
    unsigned int content_sender_initialized :1;
} websocket_client;



zend_class_entry swoole_websocket_server_ce;
zend_class_entry *swoole_websocket_server_class_entry_ptr;

zend_class_entry swoole_http_request_ce;
zend_class_entry *swoole_http_request_class_entry_ptr;

zend_class_entry swoole_websocket_frame_ce;
zend_class_entry *swoole_websocket_frame_class_entry_ptr;

static zval* php_sw_websocket_server_callbacks[2];

static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(php_http_parser *parser);

static int http_request_new(websocket_client* client TSRMLS_DC);
static void http_request_free(websocket_client *client TSRMLS_DC);

static int handshake_parse(swEventData *req TSRMLS_DC);
static int handshake_response(websocket_client *client);
static void handshake_success(websocket_client *client);

static int websocket_onHandshake(swEventData *req TSRMLS_DC);
static int websocket_onMessage(swEventData *req TSRMLS_DC);
static int websocket_onReceive(swFactory *factory, swEventData *req);
static void websocket_onClose(swServer *serv, int fd, int from_id);

#define HTTP_GLOBAL_REQUEST  0x8
#define HTTP_GLOBAL_SERVER  0x10

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

static const php_http_parser_settings http_parser_settings =
{
    NULL,
	NULL,
	NULL,
    NULL,
    NULL,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
	NULL,
	NULL
};


const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, on,         arginfo_swoole_websocket_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, start,      NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, push,       NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_websocket_frame_method[] =
{
    PHP_ME(swoole_websocket_frame, message,         NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int websocket_onMessage(swEventData *req TSRMLS_DC)
{
	int fd = req->info.fd;
    zval *zdata = php_swoole_get_data(req TSRMLS_CC);

    char *buf = Z_STRVAL_P(zdata);
    long fin = buf[0] ? 1 : 0;
    long opcode = buf[1] ? 1 : 0;

    buf += 2;

	zval *zd, *zfd, *zopcode, *zfin;
	MAKE_STD_ZVAL(zd);
	MAKE_STD_ZVAL(zfd);
	MAKE_STD_ZVAL(zopcode);
	MAKE_STD_ZVAL(zfin);
	SW_ZVAL_STRINGL(zd, buf, Z_STRLEN_P(zdata) - 2, 1);
	ZVAL_LONG(zfd, fd);
	ZVAL_LONG(zopcode, opcode);
	ZVAL_LONG(zfin, fin);
	zval **args[4];
	args[0] = &zfd;
	args[1] = &zd;
	args[2] = &zopcode;
	args[3] = &zfin;
    zval *retval;
	if (call_user_function_ex(EG(function_table), NULL, php_sw_websocket_server_callbacks[1], &retval, 4, args, 0,  NULL TSRMLS_CC) == FAILURE)

    {
        zval_ptr_dtor(&zdata);
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
    }

    //swTrace("===== message callback end======");

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
	zval_ptr_dtor(&zfd);
	zval_ptr_dtor(&zd);
	zval_ptr_dtor(&zopcode);
	zval_ptr_dtor(&zfin);

    return SW_OK;
}

static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
	websocket_client *client = parser->data;
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

    websocket_client *client = parser->data;
    char *header_name = zend_str_tolower_dup(client->current_header_name, client->current_header_name_len);

	if (memcmp(header_name, ZEND_STRL("upgrade")) == 0 && memcmp(at, ZEND_STRL("websocket")) == 0)
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
	websocket_client *client = parser->data;
    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = NULL;
    return 0;
}

static int http_request_new(websocket_client* client TSRMLS_DC)
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
	return SW_OK;
}

static void http_request_free(websocket_client *client TSRMLS_DC)
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

    /**
 *      * Free request object
 *           */
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
    zval *zcookie = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("cookie"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zcookie))
    {
        zval_ptr_dtor(&zcookie);
    }
    zval *zrequest = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("request"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zrequest))
    {
        zval_ptr_dtor(&zrequest);
    }
    zval *zserver = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("server"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(zserver))
    {
        zval_ptr_dtor(&zserver);
    }
    zval_ptr_dtor(&client->zrequest);
    client->zrequest = NULL;

    client->end = 1;
}

static int handshake_parse(swEventData *req TSRMLS_DC)
{
	int fd = req->info.fd;
	websocket_client *client = swArray_fetch(websocket_client_array, fd);
	php_http_parser *parser = &client->parser;

    /**
     * create request object
     */
    http_request_new(client TSRMLS_CC);

    parser->data = client;

    php_http_parser_init(parser, PHP_HTTP_REQUEST);

    zval *zdata = php_swoole_get_data(req TSRMLS_CC);

    long n = php_http_parser_execute(parser, &http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    zval_ptr_dtor(&zdata);
	swConnection *conn = swServer_connection_get(SwooleG.serv, fd);

    if(n < 0 || (conn->websocket_status != WEBSOCKET_STATUS_CONNECTION))
    {
		swWarn("websocket_parser failed.");
		return SW_ERR;
    }
	return SW_OK;
}


static void sha1(const char *str, unsigned char *digest)
{
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *)str, strlen(str));
    PHP_SHA1Final(digest, &context);
    return;
}


char * fetchSecKey(const char * buf)
{
  char *key;
  char *keyBegin;
  int i=0, bufLen=0;
swTrace("fetchSecKey  start");
  key=(char *)malloc(256);
  memset(key,0, 256);
  if(!buf)
    {
      return NULL;
    }
keyBegin=buf;
  bufLen=strlen(buf);
  for(i=0;i<bufLen;i++)
    {
      if(keyBegin[i]==0x0A||keyBegin[i]==0x0D)
	{
	  break;
	}
      key[i]=keyBegin[i];
    }
  
  return key;
}


char * computeAcceptKey(const char * buf)
{
  char * clientKey;
  char * serverKey; 
  char * sha1DataTemp;
  char * sha1Data;
  int i,n;
  const char * GUID="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
swTrace("computeAcceptKey start\n");
 

  if(!buf)
    {
      return NULL;
    }
  clientKey=(char *)malloc(LINE_MAX);
  memset(clientKey,0,LINE_MAX);
  clientKey=fetchSecKey(buf);
 
  if(!clientKey)
    {
      return NULL;
    }
swTrace("fetchkey success,key=%s",clientKey);
 
  strcat(clientKey,GUID);

  sha1DataTemp=sha1_hash(clientKey);
  n=strlen(sha1DataTemp);


  sha1Data=(char *)malloc(n/2+1);
  memset(sha1Data,0,n/2+1);
 
  for(i=0;i<n;i+=2)
    {      
      sha1Data[i/2]=htoi(sha1DataTemp,i,2);    
    } 

  serverKey = mybase64_encode(sha1Data, strlen(sha1Data)); 

  return serverKey;
}

static int handshake_response(websocket_client *client)
{
	//HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Version: %s\r\nKeepAlive: off\r\nContent-Length: 0\r\nServer: ZWebSocket\r\n
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
    zval *header = zend_read_property(swoole_http_request_class_entry_ptr, client->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
    HashTable *ht = Z_ARRVAL_P(header);
    zval **pData;
    if (zend_hash_find(ht, ZEND_STRS("sec-websocket-key"), (void **) &pData) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "header no sec-websocket-key");
        return SW_ERR;
    }

    convert_to_string(*pData);
//    swTrace("key: %s len:%d\n", Z_STRVAL_PP(pData), Z_STRLEN_PP(pData));

    swString *buf = swString_new(512);
    swString_append_ptr(buf, ZEND_STRL("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"));

    swString *shaBuf = swString_new(Z_STRLEN_PP(pData)+36);
    swString_append_ptr(shaBuf, Z_STRVAL_PP(pData), Z_STRLEN_PP(pData));
/*
    swString_append_ptr(shaBuf, ZEND_STRL(SW_WEBSOCKET_GUID));

    char data_str[20];
//    bzero(data_str, sizeof(data_str));
//    swTrace("sha1 start:%s\n", shaBuf->str);
    sha1(shaBuf->str, (unsigned char *) data_str);

    char encoded_value[50];
    bzero(encoded_value, sizeof(encoded_value));
//    swTrace("base64_encode start:%d\n", sizeof(data_str));
    swBase64_encode((unsigned char *) data_str, 20, encoded_value);
//    swTrace("base64_encode end:%s %d %d\n", encoded_value, encoded_len, strlen(encoded_value));

*/

    char _buf[128];
    int n = 0;


/*******fix bug****/

	char *encoded_value = computeAcceptKey( shaBuf->str);
    n = snprintf(_buf, strlen(encoded_value)+25, "Sec-WebSocket-Accept: %s\r\n", encoded_value);
//    n = snprintf(_buf, strlen(encoded_value)+25, "Sec-WebSocket-Accept: %s\r\n", encoded_value);

/****/
//    efree(data_str);
//    efree(encoded_value);
    swString_free(shaBuf);
//    swTrace("accept value: %s\n", _buf);
    swString_append_ptr(buf, _buf, n);
    swString_append_ptr(buf, ZEND_STRL("Sec-WebSocket-Version: 13\r\n"));
    swString_append_ptr(buf, ZEND_STRL("Server: swoole-websocket\r\n\r\n"));
    swTrace("websocket header len:%zd\n%s \n", buf->length, buf->str);

    int ret = swServer_tcp_send(SwooleG.serv, client->fd, buf->str, buf->length);
    swString_free(buf);
//    swTrace("handshake send: %d lenght: %d\n", client->fd, ret);
    return ret;	
}



static void handshake_success(websocket_client *client)
{
	TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    SwooleG.lock.lock(&SwooleG.lock);
    swConnection *conn = swServer_connection_get(SwooleG.serv, client->fd);
    if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
    {
        conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
    }
    SwooleG.lock.unlock(&SwooleG.lock);

    swTrace("\n\n\n\nconn ws status:%d\n\n\n", conn->websocket_status);

    if (php_sw_websocket_server_callbacks[0] != NULL)
    {
        swTrace("\n\n\n\nhandshake success\n\n\n");

		zval **args[2];
		swServer *serv = SwooleG.serv;
		zval *zserv = (zval *)serv->ptr2;
		zval *zfd;
		MAKE_STD_ZVAL(zfd);
		ZVAL_LONG(zfd, client->fd);		
		args[0] = &zserv;
		args[1] = &zfd;
		zval *retval;

		if (call_user_function_ex(EG(function_table), NULL, php_sw_websocket_server_callbacks[0], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onOpen handler error");
        }
        swTrace("===== open callback end======");
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            zval_ptr_dtor(&retval);
			zval_ptr_dtor(&zserv);
			zval_ptr_dtor(&zfd);
        }
    }
}

static int websocket_onHandshake(swEventData *req TSRMLS_DC)
{
swTrace("onhandshake\r\n");
	int fd = req->info.fd;
    websocket_client *client = swArray_alloc(websocket_client_array, fd);
    if (!client)
    {
        return SW_OK;
    }
    client->fd = fd;

	int ret = handshake_parse(req TSRMLS_CC);
	if (ret == SW_ERR)
    {
        swTrace("websocket handshake parse error\n");
        SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
    }

    ret = handshake_response(client);
    if (ret == SW_ERR)
    {
        swTrace("websocket handshake respoonse error\n");
        SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
    }
    else
    {
        handshake_success(client);
        swTrace("websocket handshake_success\n");
    }
    http_request_free(client TSRMLS_CC);
    return SW_OK;

}


static int websocket_onReceive(swFactory *factory, swEventData *req)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

	int fd = req->info.fd;

	swConnection *conn = swServer_connection_get(SwooleG.serv, fd);

    if (conn->websocket_status == WEBSOCKET_STATUS_FRAME)  //websocket callback
    {
        return websocket_onMessage(req TSRMLS_CC);
    }
	return websocket_onHandshake(req TSRMLS_CC);
}

static void websocket_onClose(swServer *serv, int fd, int from_id)
{
	websocket_client *client = swArray_fetch(websocket_client_array, fd);
    if (client)
    {
        if (client->zrequest)
        {
            TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
            http_request_free(client TSRMLS_CC);
        }
    }

    if (php_sw_callback[SW_SERVER_CB_onClose] != NULL)
    {
        php_swoole_onClose(serv, fd, from_id);
    }
}

void swoole_websocket_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_websocket_server_ce, "swoole_websocket_server", swoole_websocket_server_methods);
    swoole_websocket_server_class_entry_ptr = zend_register_internal_class_ex(&swoole_websocket_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);

    swoole_http_request_class_entry_ptr = zend_register_internal_class(&swoole_http_request_ce TSRMLS_CC);

	INIT_CLASS_ENTRY(swoole_websocket_frame_ce, "swoole_websocket_frame", swoole_websocket_frame_method);
    swoole_websocket_frame_class_entry_ptr = zend_register_internal_class(&swoole_websocket_frame_ce TSRMLS_CC);

	REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT_FRAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY_FRAME, CONST_CS | CONST_PERSISTENT);
}

PHP_METHOD( swoole_websocket_server, on)
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

    if (strncasecmp("open", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_websocket_server_callbacks[0] = callback;
    }
    else if (strncasecmp("message", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_websocket_server_callbacks[1] = callback;
    }
    else
    {
        zend_call_method_with_2_params(&getThis(), swoole_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}

PHP_METHOD( swoole_websocket_server, start)
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

    if (php_sw_websocket_server_callbacks[1] == NULL )
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onMessage callback");
        RETURN_FALSE;
    }

    websocket_client_array = swArray_new(1024, sizeof(websocket_client), 0);
    if (!websocket_client_array)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onRequest or onMessage callback");
        RETURN_FALSE;
    }

    serv->onReceive = websocket_onReceive;
    serv->open_http_protocol = 1;
	serv->onClose = websocket_onClose;

    serv->ptr2 = getThis();

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

PHP_METHOD(swoole_websocket_server, push)
{
	swString data;
    data.length = 0;
    long fd = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls|lb", &fd, &data.str, &data.length, &opcode, &fin) == FAILURE)
    {
        return;
    }
	swTrace("push to client: fd %d, data %s, opcode %d, fin %d", fd, data.str, opcode, fin);

    if (fd <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "fd[%d] is invalid.", (int )fd);
        RETURN_FALSE;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swoole_php_fatal_error(E_WARNING, "opcode max 10");
        RETURN_FALSE;
    }

    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    if (!conn || conn->websocket_status < WEBSOCKET_STATUS_HANDSHAKE)
    {
        swoole_php_fatal_error(E_WARNING, "connection[%d] is not a websocket client.", (int ) fd);
        RETURN_FALSE;
    }

    swTrace("need send:%s len:%zd\n", data.str, data.length);
    swString *response = swWebSocket_encode(&data, opcode, (int) fin);
    int ret = swServer_tcp_send(SwooleG.serv, fd, response->str, response->length);
    swTrace("need send:%s len:%zd\n", response->str, response->length);
    swString_free(response);
    SW_CHECK_RETURN(ret);
}
