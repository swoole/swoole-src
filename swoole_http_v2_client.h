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

#include "php_swoole.h"
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

    int read_cid;
    // int write_cid; // useless temporarily
    uint8_t iowait;
    swClient *client;

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

static sw_inline void http2_client_send_setting(swClient *cli, swHttp2_settings  *settings)
{
    uint16_t id = 0;
    uint32_t value = 0;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + 18];
    memset(frame, 0, sizeof(frame));
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 18, 0, 0);

    char *p = frame + SW_HTTP2_FRAME_HEADER_SIZE;
    /**
     * MAX_CONCURRENT_STREAMS
     */
    id = htons(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->max_concurrent_streams);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * MAX_FRAME_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->max_frame_size);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * INIT_WINDOW_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->window_size);
    memcpy(p, &value, sizeof(value));
    p += 4;

    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN "]\t[length=%d]", swHttp2_get_type(SW_HTTP2_TYPE_SETTINGS), 18);
    cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE + 18, 0);
}

static sw_inline void http2_client_send_window_update(swClient *cli, int stream_id, uint32_t size)
{
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_YELLOW "] stream_id=%d, size=%d", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t*) ((char *)frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, stream_id);
    cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE, 0);
}

#endif
