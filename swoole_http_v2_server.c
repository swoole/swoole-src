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

#include "php_swoole.h"
#include "swoole_http.h"

#ifdef SW_USE_HTTP2
#include "http2.h"
#include <nghttp2/nghttp2.h>

static sw_inline void http2_add_header(nghttp2_nv *headers, char *k, int kl, char *v, int vl)
{
    headers->name = (uchar*) k;
    headers->namelen = kl;
    headers->value = (uchar*) v;
    headers->valuelen = vl;
}

static int http2_build_header(http_context *ctx, uchar *buffer, int body_length TSRMLS_DC)
{
    assert(ctx->send_header == 0);

    char buf[SW_HTTP_HEADER_MAX_SIZE];
    int n;
    char *date_str;
    char intbuf[2][16];

    int ret;

    /**
     * http header
     */
    zval *zheader = ctx->response.zheader;
    int index = 0;

    nghttp2_nv nv[128];

    /**
     * http status code
     */
    if (ctx->response.status == 0)
    {
        ctx->response.status = 200;
    }

    ret = swoole_itoa(intbuf[0], ctx->response.status);
    http2_add_header(&nv[index++], ZEND_STRL(":status"), intbuf[0], ret);

    if (zheader)
    {
        int flag = 0x0;
        char *key_server = "server";
        char *key_content_length = "content-length";
        char *key_content_type = "content-type";
        char *key_date = "date";

        HashTable *ht = Z_ARRVAL_P(zheader);
        zval *value = NULL;
        char *key = NULL;
        uint32_t keylen = 0;
        int type;

        SW_HASHTABLE_FOREACH_START2(ht, key, keylen, type, value)
        {
            if (!key)
            {
                break;
            }
            if (strcmp(key, key_server) == 0)
            {
                flag |= HTTP_RESPONSE_SERVER;
            }
            else if (strcmp(key, key_content_length) == 0)
            {
                flag |= HTTP_RESPONSE_CONTENT_LENGTH;
            }
            else if (strcmp(key, key_date) == 0)
            {
                flag |= HTTP_RESPONSE_DATE;
            }
            else if (strcmp(key, key_content_type) == 0)
            {
                flag |= HTTP_RESPONSE_CONTENT_TYPE;
            }
            http2_add_header(&nv[index++], key, keylen - 1, Z_STRVAL_P(value), Z_STRLEN_P(value));
        }
        SW_HASHTABLE_FOREACH_END();

        if (!(flag & HTTP_RESPONSE_SERVER))
        {
            http2_add_header(&nv[index++], ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
        }
        if (ctx->request.method == PHP_HTTP_OPTIONS)
        {
            http2_add_header(&nv[index++], ZEND_STRL("allow"), ZEND_STRL("GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"));
        }
        else
        {
            if (!(flag & HTTP_RESPONSE_CONTENT_LENGTH) && body_length >= 0)
            {
#ifdef SW_HAVE_ZLIB
                if (ctx->gzip_enable)
                {
                    body_length = swoole_zlib_buffer->length;
                }
#endif
                ret = swoole_itoa(intbuf[1], body_length);
                http2_add_header(&nv[index++], ZEND_STRL("content-length"), intbuf[1], ret);
            }
        }
        if (!(flag & HTTP_RESPONSE_DATE))
        {
            date_str = sw_php_format_date(ZEND_STRL(SW_HTTP_DATE_FORMAT), SwooleGS->now, 0 TSRMLS_CC);
            http2_add_header(&nv[index++], ZEND_STRL("date"), date_str, strlen(date_str));
        }
        if (!(flag & HTTP_RESPONSE_CONTENT_TYPE))
        {
            http2_add_header(&nv[index++], ZEND_STRL("content-type"), ZEND_STRL("text/html"));
        }
    }
    else
    {
        http2_add_header(&nv[index++], ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
        http2_add_header(&nv[index++], ZEND_STRL("content-type"), ZEND_STRL("text/html"));

        date_str = sw_php_format_date(ZEND_STRL(SW_HTTP_DATE_FORMAT), SwooleGS->now, 0 TSRMLS_CC);
        //http2_add_header(&nv[index++], ZEND_STRL("date"), date_str, strlen(date_str));

        if (ctx->request.method == PHP_HTTP_OPTIONS)
        {
            http2_add_header(&nv[index++], ZEND_STRL("allow"), ZEND_STRL("GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"));
        }
        else if (body_length >= 0)
        {
#ifdef SW_HAVE_ZLIB
            if (ctx->gzip_enable)
            {
                body_length = swoole_zlib_buffer->length;
            }
#endif
            ret = swoole_itoa(buf, body_length);
            http2_add_header(&nv[index++], ZEND_STRL("content-length"), buf, ret);
        }
    }
    //TODO: http2 cookies
//    if (client->response.cookie)
//    {
//        swString_append(response, client->response.cookie);
//    }
    //http compress
    if (ctx->gzip_enable)
    {
#ifdef SW_HTTP_COMPRESS_GZIP
        http2_add_header(&nv[index++], ZEND_STRL("content-encoding"), ZEND_STRL("gzip"));
#else
        http2_add_header(&nv[index++], ZEND_STRL("content-encoding"), ZEND_STRL("deflate"));
#endif
    }
    ctx->send_header = 1;

    ssize_t rv;
    size_t buflen;
    size_t i;
    size_t sum = 0;

    nghttp2_hd_deflater *deflater;
    ret = nghttp2_hd_deflate_new(&deflater, 4096);
    if (ret != 0)
    {
        swoole_php_error(E_WARNING, "nghttp2_hd_deflate_init failed with error: %s\n", nghttp2_strerror(ret));
        return SW_ERR;
    }

    for (i = 0; i < index; ++i)
    {
        sum += nv[i].namelen + nv[i].valuelen;
    }

    buflen = nghttp2_hd_deflate_bound(deflater, nv, index);
    rv = nghttp2_hd_deflate_hd(deflater, (uchar *) buffer, buflen, nv, index);
    if (rv < 0)
    {
        swoole_php_error(E_WARNING, "nghttp2_hd_deflate_hd() failed with error: %s\n", nghttp2_strerror((int ) rv));
        return SW_ERR;
    }

    efree(date_str);
    nghttp2_hd_deflate_del(deflater);

    return rv;
}

int swoole_http2_do_response(http_context *ctx, swString *body)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    uchar header_buffer[8192];

    int n = http2_build_header(ctx, header_buffer, body->length TSRMLS_CC);
    swString_clear(swoole_http_buffer);

    /**
     +---------------+
     |Pad Length? (8)|
     +-+-------------+-----------------------------------------------+
     |E|                 Stream Dependency? (31)                     |
     +-+-------------+-----------------------------------------------+
     |  Weight? (8)  |
     +-+-------------+-----------------------------------------------+
     |                   Header Block Fragment (*)                 ...
     +---------------------------------------------------------------+
     |                           Padding (*)                       ...
     +---------------------------------------------------------------+
     */
    char frame_header[9];
    swHttp2_set_frame_header(frame_header, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_HEADERS, ctx->stream_id);
    swString_append_ptr(swoole_http_buffer, frame_header, 9);
    swString_append_ptr(swoole_http_buffer, header_buffer, n);

    swHttp2_set_frame_header(frame_header, SW_HTTP2_TYPE_DATA, body->length, SW_HTTP2_FLAG_END_STREAM, ctx->stream_id);
    swString_append_ptr(swoole_http_buffer, frame_header, 9);
    swString_append(swoole_http_buffer, body);

    int ret = swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
    if (ret < 0)
    {
        ctx->send_header = 0;
        return SW_ERR;
    }
    ctx->end = 1;

    return SW_OK;
}

static int http2_parse_header(swoole_http_client *client, http_context *ctx, int flags, char *in, size_t inlen)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    nghttp2_hd_inflater *inflater = client->inflater;

    if (!inflater)
    {
        int ret = nghttp2_hd_inflate_new(&inflater);
        if (ret != 0)
        {
            swoole_php_error(E_WARNING, "nghttp2_hd_inflate_init failed with error code %zd, , Error: %s", ret, nghttp2_strerror(ret));
            return SW_ERR;
        }
        client->inflater = inflater;
    }

    if (flags & SW_HTTP2_FLAG_PRIORITY)
    {
        int stream_deps = ntohl(*(int *) (in));
        uint8_t weight = in[4];
        in += 5;
        inlen -= 5;
    }

    zval *zheader = ctx->request.zheader;
    zval *zserver = ctx->request.zserver;

    ssize_t rv;
    for (;;)
    {
        nghttp2_nv nv;
        int inflate_flags = 0;
        size_t proclen;

        rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, (uchar *) in, inlen, 1);
        if (rv < 0)
        {
            swoole_php_error(E_WARNING, "inflate failed with error code %zd, Error: %s", rv, nghttp2_strerror(rv));
            return -1;
        }

        proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        //swTrace("nv.name=%s, nv.namelen=%d, nv.value=%s, nv.valuelen=%d\n", nv.name, nv.namelen, nv.value, nv.valuelen);

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            if (nv.name[0] == ':')
            {
                sw_add_assoc_stringl_ex(zserver, (char *) nv.name, nv.namelen + 1, (char *) nv.value, nv.valuelen, 1);
            }
            else
            {
                sw_add_assoc_stringl_ex(zheader, (char *) nv.name, nv.namelen + 1, (char *) nv.value, nv.valuelen, 1);
            }
        }

        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL)
        {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }

        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0)
        {
            break;
        }
    }

    rv = nghttp2_hd_inflate_change_table_size(inflater, 4096);
    if (rv != 0)
    {
        return rv;
    }
    return SW_OK;
}

/**
 * Http2
 */
int swoole_http2_onFrame(swoole_http_client *client, swEventData *req)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int fd = req->info.fd;
    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    zdata = php_swoole_get_recv_data(zdata, req TSRMLS_CC);
    char *buf = Z_STRVAL_P(zdata);

    int type = buf[3];
    int flags = buf[4];
    int stream_id = ntohl((*(int *) (buf + 5)) & 0x7fffffff);
    uint32_t length = swHttp2_get_length(buf);

    swWarn("http2 frame: type=%d, flags=%d, stream_id=%d, length=%d", type, flags, stream_id, length);

    if (type == SW_HTTP2_TYPE_HEADERS)
    {
        http_context *ctx = swoole_http_context_new(client TSRMLS_CC);
        if (!ctx)
        {
            return SW_ERR;
        }

        ctx->http2 = 1;
        ctx->stream_id = stream_id;

        http2_parse_header(client, ctx, flags, buf + SW_HTTP2_FRAME_HEADER_SIZE, length);

        zval *retval;
        zval **args[2];

        zval *zrequest_object = ctx->request.zrequest_object;
        zval *zresponse_object = ctx->response.zresponse_object;
        zval *zserver = ctx->request.zserver;

        swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
        if (!conn)
        {
            sw_zval_ptr_dtor(&zdata);
            swWarn("connection[%d] is closed.", fd);
            return SW_ERR;
        }

        sw_add_assoc_long_ex(zserver, ZEND_STRS("request_time"), SwooleGS->now);
        add_assoc_long(zserver, "server_port", swConnection_get_port(&SwooleG.serv->connection_list[conn->from_fd]));
        add_assoc_long(zserver, "remote_port", swConnection_get_port(conn));
        sw_add_assoc_string(zserver, "remote_addr", swConnection_get_ip(conn), 1);
        sw_add_assoc_string(zserver, "server_protocol", "HTTP/2", 1);
        sw_add_assoc_string(zserver, "server_software", SW_HTTP_SERVER_SOFTWARE, 1);

#ifdef __CYGWIN__
        //TODO: memory error on cygwin.
        zval_add_ref(&zobject);
        zval_add_ref(&zobject);
#endif

        args[0] = &zrequest_object;
        args[1] = &zresponse_object;

        if (sw_call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[HTTP_CALLBACK_onRequest], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onRequest handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    else if (type == SW_HTTP2_TYPE_DATA)
    {
        swoole_dump_hex(buf, 9 + 6);
    }
    return SW_OK;
}
#endif
