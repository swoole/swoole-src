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

#ifndef SWOOLE_HTTP_V2_CLIENT_H_
#define SWOOLE_HTTP_V2_CLIENT_H_

#include "php_swoole_cxx.h"
#include "swoole_http.h"

#include "http.h"
#include "http2.h"

#define HTTP2_CLIENT_HOST_HEADER_INDEX   3

typedef struct
{
    uint32_t stream_id;
    uint8_t gzip;
    uint8_t type;
    zval *response_object;
    zval *callback;
    swString *buffer;
#ifdef SW_HAVE_ZLIB
    z_stream gzip_stream;
    swString *gzip_buffer;
#endif
    zval _callback;
    zval _response_object;

    // flow control
    uint32_t remote_window_size;
    uint32_t local_window_size;

} http2_client_stream;

typedef struct
{
    char *host;
    size_t host_len;
    int port;
    uint8_t ssl;
    double timeout;
    zval *object;

    swoole::coroutine::Socket *client;

    nghttp2_hd_inflater *inflater;
    nghttp2_hd_deflater *deflater;

    uint32_t stream_id; // the next send stream id
    uint32_t last_stream_id; // the last received stream id

    swHttp2_settings local_settings;
    swHttp2_settings remote_settings;

    swHashMap *streams;

} http2_client_property;

#ifdef SW_HAVE_ZLIB
/**
 * init zlib stream
 */
static sw_inline void http2_client_init_gzip_stream(http2_client_stream *stream)
{
    stream->gzip = 1;
    memset(&stream->gzip_stream, 0, sizeof(stream->gzip_stream));
    stream->gzip_buffer = swString_new(8192);
    stream->gzip_stream.zalloc = php_zlib_alloc;
    stream->gzip_stream.zfree = php_zlib_free;
}
#endif


#endif
