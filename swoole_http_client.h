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

#ifdef __cplusplus
extern "C" {
#endif

#include "ext/standard/basic_functions.h"
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"

#include "swoole_http.h"
#include "websocket.h"
#include "thirdparty/swoole_http_parser.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

enum http_client_error_status_code
{
    HTTP_CLIENT_ESTATUS_CONNECT_FAILED = -1,
    HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT = -2,
    HTTP_CLIENT_ESTATUS_SERVER_RESET = -3,
    HTTP_CLIENT_ESTATUS_SEND_FAILED = -4,
};

enum http_client_error_flags
{
    HTTP_CLIENT_EFLAG_TIMEOUT = 1,
    HTTP_CLIENT_EFLAG_UPGRADE = 1 << 1,
};

static sw_inline void http_client_create_token(int length, char *buf)
{
    char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"§$%&/()=[]{}";
    int i;
    assert(length < 1024);
    for (i = 0; i < length; i++)
    {
        buf[i] = characters[rand() % (sizeof(characters) - 1)];
    }
    buf[length] = '\0';
}

static sw_inline int http_client_check_data(zval *data)
{
    if (Z_TYPE_P(data) != IS_ARRAY && Z_TYPE_P(data) != IS_STRING)
    {
        php_swoole_error(E_WARNING, "parameter $data must be an array or string");
        return SW_ERR;
    }
    else if (Z_TYPE_P(data) == IS_ARRAY && php_swoole_array_length(data) == 0)
    {
        php_swoole_error(E_WARNING, "parameter $data is empty");
    }
    else if (Z_TYPE_P(data) == IS_STRING && Z_STRLEN_P(data) == 0)
    {
        php_swoole_error(E_WARNING, "parameter $data is empty");
    }
    return SW_OK;
}

static sw_inline void http_client_swString_append_headers(swString* swStr, const char* key, size_t key_len, const char* data, size_t data_len)
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

#ifdef __cplusplus
}
#endif

#endif /* SWOOLE_HTTP_CLIENT_H_ */
