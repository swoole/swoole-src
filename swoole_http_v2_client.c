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
#include "swoole_http_v2_client.h"

extern zend_class_entry *swoole_http2_response_class_entry_ptr;

void http2_add_cookie(nghttp2_nv *nv, int *index, zval *cookies)
{
    char *key;
    uint32_t keylen;
    int keytype;
    zval *value = NULL;
    char *encoded_value;
    swString *buffer = SwooleTG.buffer_stack;

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(cookies), key, keylen, keytype, value)
        if (HASH_KEY_IS_STRING != keytype)
        {
            continue;
        }
        convert_to_string(value);
        if (Z_STRLEN_P(value) == 0)
        {
            continue;
        }

        swString_clear(buffer);
        swString_append_ptr(buffer, key, keylen);
        swString_append_ptr(buffer, "=", 1);

        int encoded_value_len;
        encoded_value = sw_php_url_encode(Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
        if (encoded_value)
        {
            swString_append_ptr(buffer, encoded_value, encoded_value_len);
            efree(encoded_value);
            http2_add_header(&nv[(*index)++], ZEND_STRL("cookie"), buffer->str, buffer->length);
        }
    SW_HASHTABLE_FOREACH_END();
}

int http2_client_parse_header(http2_client_property *hcc, http2_client_stream *stream , int flags, char *in, size_t inlen)
{
    zval *zresponse = stream->response_object;

    if (flags & SW_HTTP2_FLAG_PRIORITY)
    {
        //int stream_deps = ntohl(*(int *) (in));
        //uint8_t weight = in[4];
        in += 5;
        inlen -= 5;
    }

    zval *zheaders = sw_zend_read_property_array(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("headers"), 1);
    zval *zcookies = sw_zend_read_property_array(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("cookies"), 1);
    zval *zset_cookie_headers = sw_zend_read_property_array(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("set_cookie_headers"), 1);

    ssize_t rv;
    for (;;)
    {
        nghttp2_nv nv;
        int inflate_flags = 0;
        size_t proclen;

        rv = nghttp2_hd_inflate_hd(hcc->inflater, &nv, &inflate_flags, (uchar *) in, inlen, 1);
        if (rv < 0)
        {
            swoole_php_error(E_WARNING, "inflate failed, Error: %s[%zd].", nghttp2_strerror(rv), rv);
            return SW_ERR;
        }

        proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        //swTraceLog(SW_TRACE_HTTP2, "Header: %s[%d]: %s[%d]", nv.name, nv.namelen, nv.value, nv.valuelen);

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            if (nv.name[0] == ':')
            {
                if (strncasecmp((char *) nv.name + 1, "status", nv.namelen -1) == 0)
                {
                    zend_update_property_long(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("statusCode"), atoi((char *) nv.value));
                    continue;
                }
            }
#ifdef SW_HAVE_ZLIB
            else if (strncasecmp((char *) nv.name, "content-encoding", nv.namelen) == 0 && strncasecmp((char *) nv.value, "gzip", nv.valuelen) == 0)
            {
                http2_client_init_gzip_stream(stream);
                if (Z_OK != inflateInit2(&stream->gzip_stream, MAX_WBITS + 16))
                {
                    swWarn("inflateInit2() failed.");
                    return SW_ERR;
                }
            }
#endif
            else if (strncasecmp((char *) nv.name, "set-cookie", nv.namelen) == 0)
            {
                if (SW_OK != http_parse_set_cookies((char *) nv.value, nv.valuelen, zcookies, zset_cookie_headers))
                {
                    return SW_ERR;
                }
            }

            add_assoc_stringl_ex(zheaders, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);
        }

        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL)
        {
            nghttp2_hd_inflate_end_headers(hcc->inflater);
            break;
        }

        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0)
        {
            break;
        }
    }

    return SW_OK;
}

#endif
