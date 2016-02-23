/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#ifndef SWOOLE_HTTP_H_
#define SWOOLE_HTTP_H_

#include "thirdparty/php_http_parser.h"
#include "thirdparty/multipart_parser.h"

#ifdef SW_USE_HTTP2
#include <nghttp2/nghttp2.h>
#endif

enum http_callback_type
{
    HTTP_CALLBACK_onRequest = 0,
    HTTP_CALLBACK_onHandShake = 1,
};

enum http_response_flag
{
    HTTP_RESPONSE_SERVER           = 1u << 1,
    HTTP_RESPONSE_CONNECTION       = 1u << 2,
    HTTP_RESPONSE_CONTENT_LENGTH   = 1u << 3,
    HTTP_RESPONSE_DATE             = 1u << 4,
    HTTP_RESPONSE_CONTENT_TYPE     = 1u << 5,
};

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

    zval *zdata;

    zval *zrequest_object;

    zval *zserver;
    zval *zheader;
    zval *zget;
    zval *zpost;
    zval *zcookie;
    zval *zrequest;
    zval *zfiles;
} http_request;

typedef struct
{
    enum php_http_method method;
    int version;
    int status;
    swString *cookie;
    zval *zresponse_object;
    zval *zheader;
    zval *zcookie;
} http_response;

typedef struct
{
    int fd;

    uint32_t end :1;
    uint32_t send_header :1;
    uint32_t gzip_enable :1;
    uint32_t gzip_level :4;
    uint32_t chunk :1;
    uint32_t keepalive :1;
    uint32_t http2 :1;

    uint8_t priority;
    uint32_t stream_id;

    http_request request;
    http_response response;

#if PHP_MAJOR_VERSION >= 7
    struct
    {
        zval zobject;
        zval zrequest;
        zval zserver;
        zval zheader;
        zval zget;
        zval zpost;
        zval zfiles;
        zval zcookie;
        zval zdata;
    } request_stack;
    struct
    {
        zval zobject;
        zval zheader;
        zval zcookie;
    } response_stack;
#endif

} http_context;

typedef struct _swoole_http_client
{
    int fd;

    uint32_t request_read :1;
    uint32_t current_header_name_allocated :1;
    uint32_t content_sender_initialized :1;
    uint32_t http2 :1;

#ifdef SW_USE_HTTP2
    swHashMap *streams;
    nghttp2_hd_inflater *deflater;
    nghttp2_hd_inflater *inflater;
#endif

    http_context context;

    php_http_parser parser;
	multipart_parser *mt_parser;

    char *current_header_name;
    size_t current_header_name_len;

    char *current_input_name;
    char *current_form_data_name;
    size_t current_form_data_name_len;
    char *current_form_data_value;

} swoole_http_client;

/**
 * WebSocket
 */
int swoole_websocket_onMessage(swEventData *req);
int swoole_websocket_onHandshake(swoole_http_client *client);
void swoole_websocket_onOpen(swoole_http_client *client);
void swoole_websocket_onReuqest(swoole_http_client *client);
int swoole_websocket_isset_onMessage(void);
/**
 * Http Context
 */
http_context* swoole_http_context_new(swoole_http_client* client TSRMLS_DC);
void swoole_http_context_free(http_context *ctx TSRMLS_DC);
/**
 * Http v2
 */
int swoole_http2_onFrame(swoole_http_client *client, swEventData *req);
int swoole_http2_do_response(http_context *ctx, swString *body);

extern zend_class_entry swoole_http_server_ce;
extern zend_class_entry *swoole_http_server_class_entry_ptr;

extern zend_class_entry swoole_http_response_ce;
extern zend_class_entry *swoole_http_response_class_entry_ptr;

extern zend_class_entry swoole_http_request_ce;
extern zend_class_entry *swoole_http_request_class_entry_ptr;

extern swString *swoole_http_buffer;
extern swString *swoole_zlib_buffer;

extern zval* php_sw_http_server_callbacks[2];

#endif /* SWOOLE_HTTP_H_ */
