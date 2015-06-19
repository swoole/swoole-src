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
    uint32_t chunk :1;
    uint32_t keepalive :1;

    uint32_t gzip_enable :1;
    uint32_t gzip_level :4;

    uint32_t request_read :1;
    uint32_t current_header_name_allocated :1;
    uint32_t content_sender_initialized :1;

    http_request request;
    http_response response;

#if PHP_MAJOR_VERSION >= 7
    struct
    {
        zval zrequest_object;
        zval zrequest;
        zval zserver;
        zval zheader;
        zval zget;
        zval zpost;
        zval zfiles;
        zval zcookie;
    } request_stack;
    struct
    {
        zval zresponse_object;
        zval zheader;
        zval zcookie;
    } response_stack;
#endif

    php_http_parser parser;
	multipart_parser *mt_parser;

    char *current_header_name;
    size_t current_header_name_len;

    char *current_input_name;
    char *current_form_data_name;
    size_t current_form_data_name_len;
    char *current_form_data_value;

} swoole_http_client;

int swoole_websocket_onMessage(swEventData *req);
int swoole_websocket_onHandshake(swoole_http_client *client);
void swoole_websocket_onOpen(swoole_http_client *client);
int swoole_websocket_isset_onMessage(void);
void swoole_http_request_free(swoole_http_client *client TSRMLS_DC);

extern zend_class_entry swoole_http_server_ce;
extern zend_class_entry *swoole_http_server_class_entry_ptr;

extern zend_class_entry swoole_http_response_ce;
extern zend_class_entry *swoole_http_response_class_entry_ptr;

extern zend_class_entry swoole_http_request_ce;
extern zend_class_entry *swoole_http_request_class_entry_ptr;

extern swString *swoole_http_buffer;

#endif /* SWOOLE_HTTP_H_ */
