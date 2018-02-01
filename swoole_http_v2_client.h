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

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
extern voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size);
extern void php_zlib_free(voidpf opaque, voidpf address);
extern int http_response_uncompress(z_stream *stream, swString *buffer, char *body, int length);
#endif

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
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _response_object;
#endif
} http2_client_stream;

typedef struct
{
    uint8_t ssl;
    uint8_t connecting;
    uint8_t ready;
    uint8_t send_setting;

#ifdef SW_COROUTINE
    uint8_t iowait;
    int cid;
    swClient *client;
#endif

    uint32_t stream_id;

    uint32_t window_size;
    uint32_t max_concurrent_streams;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;

    char *host;
    zend_size_t host_len;
    int port;

    nghttp2_hd_inflater *inflater;
    zval *object;
    double timeout;

    swLinkedList *requests;
    swLinkedList *stream_requests;
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

int http2_client_parse_header(http2_client_property *hcc, http2_client_stream *stream , int flags, char *in, size_t inlen);

static sw_inline void http2_client_send_setting(swClient *cli)
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
    value = htonl(SW_HTTP2_MAX_CONCURRENT_STREAMS);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * MAX_FRAME_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(SW_HTTP2_MAX_FRAME_SIZE);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * INIT_WINDOW_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(65535);
    memcpy(p, &value, sizeof(value));
    p += 4;

    swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN"]\t[length=%d]", swHttp2_get_type(SW_HTTP2_TYPE_SETTINGS), 18);
    cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE + 18, 0);
}

static sw_inline void http2_add_header(nghttp2_nv *headers, char *k, int kl, char *v, int vl)
{
    headers->name = (uchar*) k;
    headers->namelen = kl;
    headers->value = (uchar*) v;
    headers->valuelen = vl;

    swTrace("k=%s, len=%d, v=%s, len=%d", k, kl, v, vl);
}

void http2_add_cookie(nghttp2_nv *nv, int *index, zval *cookies TSRMLS_DC);

extern swString *cookie_buffer;
extern zend_class_entry *swoole_client_class_entry_ptr;

#endif
