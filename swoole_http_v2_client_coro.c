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
#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "swoole_http_v2_client.h"

extern zend_class_entry *swoole_http2_response_class_entry_ptr;

static zend_class_entry swoole_http2_client_coro_ce;
static zend_class_entry *swoole_http2_client_coro_class_entry_ptr;

static zend_class_entry swoole_http2_request_coro_ce;
static zend_class_entry *swoole_http2_request_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, request)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_write, 0, 0, 2)
    ZEND_ARG_INFO(0, stream_id)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, end_stream)
ZEND_END_ARG_INFO()

enum
{
    HTTP2_CLIENT_CORO_CONTEXT  = 0,
    HTTP2_CLIENT_CORO_PROPERTY = 1,
};

static PHP_METHOD(swoole_http2_client_coro, __construct);
static PHP_METHOD(swoole_http2_client_coro, __destruct);
static PHP_METHOD(swoole_http2_client_coro, set);
static PHP_METHOD(swoole_http2_client_coro, send);
static PHP_METHOD(swoole_http2_client_coro, recv);
static PHP_METHOD(swoole_http2_client_coro, connect);
static PHP_METHOD(swoole_http2_client_coro, close);
static PHP_METHOD(swoole_http2_client_coro, write);

static int http2_client_send_request(zval *zobject, zval *request TSRMLS_DC);
static void http2_client_stream_free(void *ptr);
static void http2_client_onConnect(swClient *cli);
static void http2_client_onClose(swClient *cli);
static void http2_client_onError(swClient *cli);
static void http2_client_onReceive(swClient *cli, char *buf, uint32_t _length);

static const zend_function_entry swoole_http2_client_methods[] =
{
    PHP_ME(swoole_http2_client_coro, __construct, arginfo_swoole_http2_client_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http2_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http2_client_coro, set,      arginfo_swoole_http2_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, connect,  arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, send,      arginfo_swoole_http2_client_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, recv,      arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, write,     arginfo_swoole_http2_client_coro_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, close,     arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_http2_client_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http2_client_coro_ce, "Swoole\\Coroutine\\Http2\\Client", swoole_http2_client_methods);
    swoole_http2_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_http2_client_coro_ce);

    INIT_CLASS_ENTRY(swoole_http2_request_coro_ce, "Swoole\\Coroutine\\Http2\\Request", NULL);
    swoole_http2_request_coro_class_entry_ptr = zend_register_internal_class(&swoole_http2_request_coro_ce);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Http2\\Client", swoole_http2_client_coro_class_entry_ptr);
        sw_zend_register_class_alias("Co\\Http2\\Request", swoole_http2_request_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_client_coro_class_entry_ptr, SW_STRL("reuse")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("reuseCount")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_client_coro_class_entry_ptr, SW_STRL("host")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("port")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_null(swoole_http2_request_coro_class_entry_ptr, SW_STRL("method")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_coro_class_entry_ptr, SW_STRL("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_coro_class_entry_ptr, SW_STRL("data")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_request_coro_class_entry_ptr, SW_STRL("pipeline")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_coro_class_entry_ptr, SW_STRL("files")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
}

static PHP_METHOD(swoole_http2_client_coro, __construct)
{
    char *host;
    zend_size_t host_len;
    long port = 80;
    zend_bool ssl = SW_FALSE;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &host, &host_len, &port, &ssl) == FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
        zend_throw_exception(swoole_exception_class_entry_ptr, "host is empty.", SW_ERROR_INVALID_PARAMS TSRMLS_CC);
        RETURN_FALSE;
    }

    http2_client_property *hcc;
    hcc = (http2_client_property*) emalloc(sizeof(http2_client_property));
    bzero(hcc, sizeof(http2_client_property));
    swoole_set_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY, hcc);

    php_context *context = emalloc(sizeof(php_context));
    swoole_set_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT, context);
    context->onTimeout = NULL;
#if PHP_MAJOR_VERSION < 7
    context->coro_params = getThis();
#else
    context->coro_params = *getThis();
#endif

    hcc->streams = swHashMap_new(8, http2_client_stream_free);
    hcc->stream_id = 1;

    long type = SW_FLAG_ASYNC | SW_SOCK_TCP;
    if (ssl)
    {
#ifdef SW_USE_OPENSSL
        type |= SW_SOCK_SSL;
        hcc->ssl = 1;
#else
        swoole_php_fatal_error(E_ERROR, "require openssl library.");
#endif
    }

    zend_update_property_long(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), type TSRMLS_CC);

    hcc->host = estrndup(host, host_len);
    hcc->host_len = host_len;
    hcc->port = port;
}

static PHP_METHOD(swoole_http2_client_coro, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    if (Z_TYPE_P(zset) != IS_ARRAY)
    {
        RETURN_FALSE;
    }
    zval *zsetting = php_swoole_read_init_property(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting") TSRMLS_CC);
    sw_php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    RETURN_TRUE;
}

static int http2_client_build_header(zval *zobject, zval *req, char *buffer, int buffer_len TSRMLS_DC)
{
    char *date_str = NULL;
    int ret;
    int index = 0;
    int find_host = 0;

    zval *cookies = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("cookies"), 1 TSRMLS_CC);
    zval *method = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("method"), 1 TSRMLS_CC);
    zval *path = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("path"), 1 TSRMLS_CC);
    zval *headers = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("headers"), 1 TSRMLS_CC);

    nghttp2_nv nv[1024];
    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    if (ZVAL_IS_NULL(method) || Z_TYPE_P(method) != IS_STRING || Z_STRLEN_P(method) == 0)
    {
        http2_add_header(&nv[index++], ZEND_STRL(":method"), ZEND_STRL("GET"));
    }
    else
    {
        http2_add_header(&nv[index++], ZEND_STRL(":method"), Z_STRVAL_P(method), Z_STRLEN_P(method));
    }
    if (ZVAL_IS_NULL(path) || Z_TYPE_P(path) != IS_STRING || Z_STRLEN_P(path) == 0)
    {
        http2_add_header(&nv[index++], ZEND_STRL(":path"), "/", 1);
    }
    else
    {
        http2_add_header(&nv[index++], ZEND_STRL(":path"), Z_STRVAL_P(path), Z_STRLEN_P(path));
    }
    if (hcc->ssl)
    {
        http2_add_header(&nv[index++], ZEND_STRL(":scheme"), ZEND_STRL("https"));
    }
    else
    {
        http2_add_header(&nv[index++], ZEND_STRL(":scheme"), ZEND_STRL("http"));
    }
    //Host
    index++;

    if (headers && !ZVAL_IS_NULL(headers))
    {
        HashTable *ht = Z_ARRVAL_P(headers);
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
            if (*key == ':')
            {
                continue;
            }
            if (strncasecmp("Host", key, keylen) == 0)
            {
                http2_add_header(&nv[HTTP2_CLIENT_HOST_HEADER_INDEX], ZEND_STRL(":authority"), Z_STRVAL_P(value), Z_STRLEN_P(value));
                find_host = 1;
            }
            else
            {
                http2_add_header(&nv[index++], key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void)type;
    }
    if (!find_host)
    {
        http2_add_header(&nv[HTTP2_CLIENT_HOST_HEADER_INDEX], ZEND_STRL(":authority"), hcc->host, hcc->host_len);
    }

    //http cookies
    if (cookies && !ZVAL_IS_NULL(cookies))
    {
        http2_add_cookie(nv, &index, cookies TSRMLS_CC);
    }

    ssize_t rv;
    size_t buflen;
    size_t i;
    size_t sum = 0;

#if 0
    for (i = 0; i < index; ++i)
    {
        swTraceLog(SW_TRACE_HTTP2, "Header[%d]: "SW_ECHO_CYAN_BLUE"=%s", i, nv[i].name, nv[i].value);
    }
#endif

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
    if (buflen > buffer_len)
    {
        swoole_php_error(E_WARNING, "header is too large.");
        return SW_ERR;
    }
    rv = nghttp2_hd_deflate_hd(deflater, (uchar *) buffer, buflen, nv, index);
    if (rv < 0)
    {
        swoole_php_error(E_WARNING, "nghttp2_hd_deflate_hd() failed with error: %s\n", nghttp2_strerror((int ) rv));
        return SW_ERR;
    }

    if (date_str)
    {
        efree(date_str);
    }

    nghttp2_hd_deflate_del(deflater);

    return rv;
}

static void http2_client_onReceive(swClient *cli, char *buf, uint32_t _length)
{
    int type = buf[3];
    int flags = buf[4];
    int error_code;
    int stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;
    uint32_t length = swHttp2_get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    zval *zobject = cli->object;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];

    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);

    uint16_t id;
    uint32_t value;
    swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_YELLOW"]\tflags=%d, stream_id=%d, length=%d", swHttp2_get_type(type), flags, stream_id, length);

    if (type == SW_HTTP2_TYPE_SETTINGS)
    {
        if (flags & SW_HTTP2_FLAG_ACK)
        {
            return;
        }

        while(length > 0)
        {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            switch (id)
            {
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                hcc->max_concurrent_streams = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%d.", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                hcc->window_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: init_window_size=%d.", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                hcc->max_frame_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_frame_size=%d.", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                hcc->max_header_list_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_header_list_size=%d.", value);
                break;
            default:
                swWarn("unknown option[%d].", id);
                break;
            }
            buf += sizeof(id) + sizeof(value);
            length -= sizeof(id) + sizeof(value);
        }

        swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 0, SW_HTTP2_FLAG_ACK, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", ACK, STREAM#%d]\t[length=%d]", swHttp2_get_type(SW_HTTP2_TYPE_SETTINGS), stream_id, length);
        cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE, 0);
        return;
    }
    else if (type == SW_HTTP2_TYPE_WINDOW_UPDATE)
    {
        hcc->window_size = ntohl(*(int *) buf);
        swTraceLog(SW_TRACE_HTTP2, "update: window_size=%d.", hcc->window_size);
        return;
    }
    else if (type == SW_HTTP2_TYPE_PING)
    {
        swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, stream_id);
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, buf + SW_HTTP2_FRAME_HEADER_SIZE, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", STREAM#%d]", swHttp2_get_type(SW_HTTP2_FRAME_PING_PAYLOAD_SIZE), stream_id);
        cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, 0);
        return;
    }
    else if (type == SW_HTTP2_TYPE_GOAWAY)
    {
        int last_stream_id = htonl(*(int *) (buf));
        buf += 4;
        error_code = htonl(*(int *) (buf));
        swWarn("["SW_ECHO_RED"] last_stream_id=%d, error_code=%d.", "GOAWAY", last_stream_id, error_code);
        
        zval* retval;
        sw_zend_call_method_with_0_params(&zobject, swoole_http2_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        if (hcc->iowait == 0)
        {
            return;
        }
    }
    else if (type == SW_HTTP2_TYPE_RST_STREAM)
    {
        error_code = htonl(*(int *) (buf));
        swWarn("["SW_ECHO_RED"] stream_id=%d, error_code=%d.", "RST_STREAM", stream_id, error_code);

        if (hcc->iowait == 0)
        {
            return;
        }
    }

    http2_client_stream *stream = swHashMap_find_int(hcc->streams, stream_id);
    // stream has closed
    if (stream == NULL)
    {
        return;
    }
    if (type == SW_HTTP2_TYPE_HEADERS)
    {
        http2_client_parse_header(hcc, stream, flags, buf, length);
    }
    else if (type == SW_HTTP2_TYPE_DATA)
    {
        if (!stream->buffer)
        {
            stream->buffer = swString_new(8192);
        }
#ifdef SW_HAVE_ZLIB
        if (stream->gzip)
        {
            if (http_response_uncompress(&stream->gzip_stream, stream->gzip_buffer, buf, length) == SW_ERR)
            {
                return;
            }
            swString_append_ptr(stream->buffer, stream->gzip_buffer->str, stream->gzip_buffer->length);
        }
        else
#endif
        {
            swString_append_ptr(stream->buffer, buf, length);
        }
    }

    if ((type == SW_HTTP2_TYPE_DATA && stream->type == SW_HTTP2_STREAM_PIPELINE)
            || (stream->type == SW_HTTP2_STREAM_NORMAL && (flags & SW_HTTP2_FLAG_END_STREAM))
            || type == SW_HTTP2_TYPE_RST_STREAM || type == SW_HTTP2_TYPE_GOAWAY)
    {
        zval *zresponse = stream->response_object;
        zval *retval = NULL;

        if (type == SW_HTTP2_TYPE_RST_STREAM)
        {
            zend_update_property_long(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("statusCode"), -3 TSRMLS_CC);
            zend_update_property_long(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("errCode"), error_code TSRMLS_CC);
        }

        if (stream->buffer)
        {
            zend_update_property_stringl(swoole_http2_response_class_entry_ptr, stream->response_object, ZEND_STRL("body"), stream->buffer->str, stream->buffer->length TSRMLS_CC);
        }

        hcc->iowait = 0;
        if (stream->type == SW_HTTP2_STREAM_NORMAL)
        {
            swHashMap_del_int(hcc->streams, stream_id);
        }
        else if (stream->buffer)
        {
            swString_clear(stream->buffer);
        }

        php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
        int ret = coro_resume(context, zresponse, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&zresponse);
    }
}

static void http2_client_stream_free(void *ptr)
{
    http2_client_stream *stream = ptr;
    if (stream->buffer)
    {
        swString_free(stream->buffer);
    }
#ifdef SW_HAVE_ZLIB
    if (stream->gzip)
    {
        inflateEnd(&stream->gzip_stream);
        swString_free(stream->gzip_buffer);
    }
#endif
    efree(stream);
}

static int http2_client_send_request(zval *zobject, zval *req TSRMLS_DC)
{
    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;

    zval *headers = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("headers"), 1 TSRMLS_CC);
    zval *post_data = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("data"), 1 TSRMLS_CC);
    zval *pipeline = sw_zend_read_property(swoole_http2_request_coro_class_entry_ptr, req, ZEND_STRL("pipeline"), 1 TSRMLS_CC);

    if (!ZVAL_IS_NULL(post_data))
    {
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            sw_add_assoc_stringl_ex(headers, ZEND_STRS("content-type"), ZEND_STRL("application/x-www-form-urlencoded"), 1);
        }
    }
    /**
     * send header
     */
    char buffer[8192];
    int n = http2_client_build_header(zobject, req, buffer + SW_HTTP2_FRAME_HEADER_SIZE, sizeof(buffer) - SW_HTTP2_FRAME_HEADER_SIZE TSRMLS_CC);
    if (n <= 0)
    {
        swWarn("http2_client_build_header() failed.");
        return -1;
    }

    http2_client_stream *stream = emalloc(sizeof(http2_client_stream));
    memset(stream, 0, sizeof(http2_client_stream));

    zval *response_object;
    SW_MAKE_STD_ZVAL(response_object);
    object_init_ex(response_object, swoole_http2_response_class_entry_ptr);

    stream->stream_id = hcc->stream_id;
    stream->response_object = response_object;
    stream->type = Z_BVAL_P(pipeline) ? SW_HTTP2_STREAM_PIPELINE : SW_HTTP2_STREAM_NORMAL;

    if (ZVAL_IS_NULL(post_data))
    {
        //pipeline
        if (stream->type == SW_HTTP2_STREAM_PIPELINE)
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_HEADERS, hcc->stream_id);
        }
        else
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_STREAM | SW_HTTP2_FLAG_END_HEADERS, hcc->stream_id);
        }
    }
    else
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_HEADERS, hcc->stream_id);
    }

    sw_copy_to_stack(stream->response_object, stream->_response_object);

    zend_update_property_long(swoole_http2_response_class_entry_ptr, response_object, ZEND_STRL("streamId"), stream->stream_id TSRMLS_CC);

    swHashMap_add_int(hcc->streams, hcc->stream_id, stream);
    swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", STREAM#%d] length=%d", swHttp2_get_type(SW_HTTP2_TYPE_HEADERS), hcc->stream_id, n);
    cli->send(cli, buffer, n + SW_HTTP2_FRAME_HEADER_SIZE, 0);

    /**
     * send body
     */
    if (!ZVAL_IS_NULL(post_data))
    {
        int flag = stream->type == SW_HTTP2_STREAM_PIPELINE ? 0 : SW_HTTP2_FLAG_END_STREAM;
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            zend_size_t len;
            smart_str formstr_s = { 0 };
            char *formstr = sw_http_build_query(post_data, &len, &formstr_s TSRMLS_CC);
            if (formstr == NULL)
            {
                swoole_php_error(E_WARNING, "http_build_query failed.");
                return -1;
            }
            memset(buffer, 0, SW_HTTP2_FRAME_HEADER_SIZE);
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, len, flag, hcc->stream_id);
            swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%d", swHttp2_get_type(SW_HTTP2_TYPE_DATA), hcc->stream_id, len);
            cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0);
            cli->send(cli, formstr, len, 0);
            smart_str_free(&formstr_s);
        }
        else
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, Z_STRLEN_P(post_data), flag, hcc->stream_id);
            swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%d", swHttp2_get_type(SW_HTTP2_TYPE_DATA), hcc->stream_id, Z_STRLEN_P(post_data));
            cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0);
            cli->send(cli, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data), 0);
        }
    }

    hcc->stream_id += 2;
    return stream->stream_id;
}

static int http2_client_send_data(http2_client_property *hcc, uint32_t stream_id, zval *data, zend_bool end TSRMLS_DC)
{
    swClient *cli = hcc->client;

    char buffer[8192];
    http2_client_stream *stream = swHashMap_find_int(hcc->streams, stream_id);
    if (stream == NULL || stream->type != SW_HTTP2_STREAM_PIPELINE)
    {
        return -1;
    }

    int flag = end ? SW_HTTP2_FLAG_END_STREAM : 0;

    if (Z_TYPE_P(data) == IS_ARRAY)
    {
        zend_size_t len;
        smart_str formstr_s = { 0 };
        char *formstr = sw_http_build_query(data, &len, &formstr_s TSRMLS_CC);
        if (formstr == NULL)
        {
            swoole_php_error(E_WARNING, "http_build_query failed.");
            return -1;
        }
        memset(buffer, 0, SW_HTTP2_FRAME_HEADER_SIZE);
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, len, flag, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%d", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, len);
        cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0);
        cli->send(cli, formstr, len, 0);
        smart_str_free(&formstr_s);
    }
    else if (Z_TYPE_P(data) == IS_STRING)
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, Z_STRLEN_P(data), flag, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%d", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, Z_STRLEN_P(data));
        cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0);
        cli->send(cli, Z_STRVAL_P(data), Z_STRLEN_P(data), 0);
    }
    else
    {
        swoole_php_error(E_WARNING, "unknown data type[%d].", Z_TYPE_P(data) );
        return -1;
    }
    return SW_OK;
}

static PHP_METHOD(swoole_http2_client_coro, send)
{
    zval *request;

    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;
    
    if (!cli || !cli->socket || cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "The connection is closed.");
        RETURN_FALSE;
    }
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &request) == FAILURE)
    {
        return;
    }
    if (SW_Z_TYPE_P(request) != IS_OBJECT)
    {
        error: swoole_php_fatal_error(E_ERROR, "object is not instanceof swoole_process.");
        RETURN_FALSE;
    }
    if (!instanceof_function(Z_OBJCE_P(request), swoole_http2_request_coro_class_entry_ptr TSRMLS_CC))
    {
        goto error;
    }

    int stream_id = http2_client_send_request(getThis(), request TSRMLS_CC);
    if (stream_id < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(stream_id);
    }
}

static PHP_METHOD(swoole_http2_client_coro, recv)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;

    if (!cli || !cli->socket || cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "The connection is closed.");
        RETURN_FALSE;
    }

    php_context *context = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT);
    hcc->cid = COROG.current_coro->cid;
    coro_save(context);
    hcc->iowait = 1;
    coro_yield();
}

static void http2_client_onConnect(swClient *cli)
{
    zval *zobject = cli->object;
    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);

    zend_update_property_bool(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 1 TSRMLS_CC);

    cli->send(cli, ZEND_STRL("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0);
    cli->open_length_check = 1;
    cli->protocol.get_package_length = swHttp2_get_frame_length;
    cli->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;

    hcc->ready = 1;
    hcc->stream_id = 1;
    hcc->send_setting = 1;
    if (hcc->send_setting)
    {
        http2_client_send_setting(cli);
    }
    zval *result;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 1);

    zval *retval = NULL;

    php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void http2_client_onClose(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zobject = cli->object;
    zend_update_property_bool(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);

    if (cli->released)
    {
        return;
    }

    php_swoole_client_free(zobject, cli TSRMLS_CC);
    http2_client_property *hcc = swoole_get_property(zobject,HTTP2_CLIENT_CORO_PROPERTY);
    if (!hcc->iowait)
    {
        return;
    }

    zval *result;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 0);

    zval *retval;
    php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    hcc->cid = 0;
}

static void http2_client_onError(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zdata;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zdata);
    //return false
    ZVAL_BOOL(zdata, 0);

    zval *zobject = cli->object;
    php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);

    if (!cli->released)
    {
        php_swoole_client_free(zobject, cli TSRMLS_CC);
    }

    coro_resume(context, zdata, &retval);
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
}

static PHP_METHOD(swoole_http2_client_coro, __destruct)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    if (hcc)
    {
        if (hcc->inflater)
        {
            nghttp2_hd_inflate_del(hcc->inflater);
            hcc->inflater = NULL;
        }
        if (hcc->host)
        {
            efree(hcc->host);
            hcc->host = NULL;
        }

        swHashMap_free(hcc->streams);
        efree(hcc);
        swoole_set_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY, NULL);
    }

    php_context *context = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT);
    efree(context);
    swoole_set_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT, NULL);

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        return;
    }

    zval *zobject = getThis();
    zval *retval = NULL;
    sw_zend_call_method_with_0_params(&zobject, swoole_http2_client_coro_class_entry_ptr, NULL, "close", &retval);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static PHP_METHOD(swoole_http2_client_coro, close)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        php_swoole_client_free(getThis(), cli TSRMLS_CC);
        RETURN_FALSE;
    }

    int ret = SW_OK;
    cli->released = 1;
    ret = cli->close(cli);
    php_swoole_client_free(getThis(), cli TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http2_client_coro, connect)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);

    php_swoole_check_reactor();
    swClient *cli = php_swoole_client_new(getThis(), hcc->host, hcc->host_len, hcc->port);
    if (cli == NULL)
    {
        RETURN_FALSE;
    }
    hcc->client = cli;

    zval *ztmp;
    HashTable *vht;
    zval *zset = sw_zend_read_property(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        vht = Z_ARRVAL_P(zset);
        /**
         * timeout
         */
        if (php_swoole_array_get_value(vht, "timeout", ztmp))
        {
            convert_to_double(ztmp);
            hcc->timeout = (double) Z_DVAL_P(ztmp);
        }
        //client settings
        php_swoole_client_check_setting(hcc->client, zset TSRMLS_CC);
    }

    swoole_set_object(getThis(), cli);

    cli->onConnect = http2_client_onConnect;
    cli->onClose = http2_client_onClose;
    cli->onError = http2_client_onError;
    cli->onReceive = http2_client_onReceive;
    cli->http2 = 1;

    cli->open_eof_check = 0;
    cli->open_length_check = 0;
    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;

    if (cli->connect(cli, hcc->host, hcc->port, hcc->timeout, 0) < 0)
    {
        RETURN_FALSE;
    }

    php_context *context = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT);
    cli->object = &context->coro_params;
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http2_client_coro, write)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;

    if (!cli || !cli->socket || cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "The connection is closed.");
        RETURN_FALSE;
    }

    long stream_id;
    zval *data;
    zend_bool end = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|b", &stream_id, &data, &end) == FAILURE)
    {
        return;
    }
    SW_CHECK_RETURN(http2_client_send_data(hcc, stream_id, data, end TSRMLS_CC));
}

#endif
#endif
