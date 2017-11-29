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

#ifndef SWOOLE_HTTP_CLIENT_H_
#define SWOOLE_HTTP_CLIENT_H_

#include "ext/standard/basic_functions.h"
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"

#include "websocket.h"
#include "thirdparty/php_http_parser.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

enum http_client_state
{
    HTTP_CLIENT_STATE_WAIT,
    HTTP_CLIENT_STATE_READY,
    HTTP_CLIENT_STATE_BUSY,
    //WebSocket
    HTTP_CLIENT_STATE_UPGRADE,
    HTTP_CLIENT_STATE_WAIT_CLOSE,
    HTTP_CLIENT_STATE_CLOSED,
};

#ifdef SW_COROUTINE
typedef enum
{
    HTTP_CLIENT_STATE_DEFER_INIT,
    HTTP_CLIENT_STATE_DEFER_SEND,
    HTTP_CLIENT_STATE_DEFER_WAIT,
    HTTP_CLIENT_STATE_DEFER_DONE,
} http_client_defer_state;
#endif

typedef struct
{
    zval *onConnect;
    zval *onError;
    zval *onClose;
    zval *onMessage;
    zval *onResponse;

#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _request_body;
    zval _request_header;
    zval _request_upload_files;
    zval _download_file;
    zval _cookies;
    zval _onConnect;
    zval _onError;
    zval _onClose;
    zval _onMessage;
#endif

    zval *cookies;
    zval *request_header;
    zval *request_body;
    zval *request_upload_files;
    zval *download_file;
    off_t download_offset;
    char *request_method;
    int callback_index;

    double request_timeout;

    uint8_t shutdown;

#ifdef SW_COROUTINE
    zend_bool defer;//0 normal 1 wait for receive
    zend_bool defer_result;//0
    zend_bool defer_chunk_status;// 0 1 now use rango http->complete
    http_client_defer_state defer_status;
    int cid;
#endif

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

    swTimer_node *timer;

    char *tmp_header_field_name;
    int tmp_header_field_name_len;

#ifdef SW_HAVE_ZLIB
    z_stream gzip_stream;
    swString *gzip_buffer;
#endif

    /**
     * download page
     */
    int file_fd;

    php_http_parser parser;

    swString *body;

    uint8_t state;       //0 wait 1 ready 2 busy
    uint8_t keep_alive;  //0 no 1 keep
    uint8_t upgrade;
    uint8_t gzip;
    uint8_t chunked;     //Transfer-Encoding: chunked
    uint8_t completed;
    uint8_t websocket_mask;
    uint8_t download;    //save http response to file
    uint8_t header_completed;

} http_client;

int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length);
int http_client_parser_on_headers_complete(php_http_parser *parser);
int http_client_parser_on_message_complete(php_http_parser *parser);

http_client* http_client_create(zval *object TSRMLS_DC);
void http_client_free(zval *object TSRMLS_DC);

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

static sw_inline int http_client_check_data(zval *data TSRMLS_DC)
{
    if (Z_TYPE_P(data) != IS_ARRAY && Z_TYPE_P(data) != IS_STRING)
    {
        swoole_php_error(E_WARNING, "parameter $data must be an array or string.");
        return SW_ERR;
    }
    else if (Z_TYPE_P(data) == IS_ARRAY && php_swoole_array_length(data) == 0)
    {
        swoole_php_error(E_WARNING, "parameter $data is empty.");
    }
    else if (Z_TYPE_P(data) == IS_STRING && Z_STRLEN_P(data) == 0)
    {
        swoole_php_error(E_WARNING, "parameter $data is empty.");
    }
    return SW_OK;
}

static sw_inline void http_client_swString_append_headers(swString* swStr, char* key, zend_size_t key_len, char* data, zend_size_t data_len)
{
    swString_append_ptr(swStr, key, key_len);
    swString_append_ptr(swStr, ZEND_STRL(": "));
    swString_append_ptr(swStr, data, data_len);
    swString_append_ptr(swStr, ZEND_STRL("\r\n"));
}

static sw_inline void http_client_append_content_length(swString* buf, int length)
{
    char content_length_str[32];
    int n = snprintf(content_length_str, sizeof(content_length_str), "Content-Length: %d\r\n\r\n", length);
    swString_append_ptr(buf, content_length_str, n);
}

#ifdef SW_HAVE_ZLIB
extern swString *swoole_zlib_buffer;
#endif

#endif /* SWOOLE_HTTP_CLIENT_H_ */
