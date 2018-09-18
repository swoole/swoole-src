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

static zend_class_entry swoole_http2_client_coro_ce;
static zend_class_entry *swoole_http2_client_coro_class_entry_ptr;

static zend_class_entry swoole_http2_request_coro_ce;
static zend_class_entry *swoole_http2_request_class_entry_ptr;

static zend_class_entry swoole_http2_response_ce;
zend_class_entry *swoole_http2_response_class_entry_ptr;

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_stats, 0, 0, 0)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_isStreamExist, 0, 0, 1)
    ZEND_ARG_INFO(0, stream_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, request)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_write, 0, 0, 2)
    ZEND_ARG_INFO(0, stream_id)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, end_stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_goaway, 0, 0, 0)
    ZEND_ARG_INFO(0, error_code)
    ZEND_ARG_INFO(0, debug_data)
ZEND_END_ARG_INFO()

enum
{
    HTTP2_CLIENT_CORO_CONTEXT  = 0,
    HTTP2_CLIENT_CORO_PROPERTY = 1,
};

static PHP_METHOD(swoole_http2_client_coro, __construct);
static PHP_METHOD(swoole_http2_client_coro, __destruct);
static PHP_METHOD(swoole_http2_client_coro, set);
static PHP_METHOD(swoole_http2_client_coro, connect);
static PHP_METHOD(swoole_http2_client_coro, stats);
static PHP_METHOD(swoole_http2_client_coro, isStreamExist);
static PHP_METHOD(swoole_http2_client_coro, send);
static PHP_METHOD(swoole_http2_client_coro, write);
static PHP_METHOD(swoole_http2_client_coro, recv);
static PHP_METHOD(swoole_http2_client_coro, goaway);
static PHP_METHOD(swoole_http2_client_coro, close);

static uint32_t http2_client_send_request(zval *zobject, zval *request TSRMLS_DC);
static void http2_client_stream_free(void *ptr);
static void http2_client_onConnect(swClient *cli);
static void http2_client_onClose(swClient *cli);
static void http2_client_onTimeout(swTimer *timer, swTimer_node *tnode);
static void http2_client_onReceive(swClient *cli, char *buf, uint32_t _length);

static const zend_function_entry swoole_http2_client_methods[] =
{
    PHP_ME(swoole_http2_client_coro, __construct,   arginfo_swoole_http2_client_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http2_client_coro, __destruct,    arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http2_client_coro, set,           arginfo_swoole_http2_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, connect,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, stats,         arginfo_swoole_http2_client_coro_stats, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, isStreamExist, arginfo_swoole_http2_client_coro_isStreamExist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, send,          arginfo_swoole_http2_client_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, write,         arginfo_swoole_http2_client_coro_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, recv,          arginfo_swoole_http2_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, goaway,        arginfo_swoole_http2_client_coro_goaway, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, close,         arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_http2_client_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http2_client_coro_ce, "Swoole\\Coroutine\\Http2\\Client", swoole_http2_client_methods);
    swoole_http2_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_http2_client_coro_ce);

    INIT_CLASS_ENTRY(swoole_http2_request_coro_ce, "Swoole\\Http2\\Request", NULL);
    swoole_http2_request_class_entry_ptr = zend_register_internal_class(&swoole_http2_request_coro_ce);

    INIT_CLASS_ENTRY(swoole_http2_response_ce, "Swoole\\Http2\\Response", NULL);
    swoole_http2_response_class_entry_ptr = zend_register_internal_class(&swoole_http2_response_ce TSRMLS_CC);

    if (SWOOLE_G(use_namespace))
    {
        sw_zend_register_class_alias("swoole_http2_request", swoole_http2_request_class_entry_ptr);
        sw_zend_register_class_alias("swoole_http2_response", swoole_http2_response_class_entry_ptr);
    }
    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Http2\\Client", swoole_http2_client_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("errMsg")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_client_coro_class_entry_ptr, SW_STRL("host")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_client_coro_class_entry_ptr, SW_STRL("port")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("path")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("method")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("cookies")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("data")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_request_class_entry_ptr, SW_STRL("pipeline")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_request_class_entry_ptr, SW_STRL("files")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_long(swoole_http2_response_class_entry_ptr, SW_STRL("streamId")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_response_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http2_response_class_entry_ptr, SW_STRL("statusCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http2_response_class_entry_ptr, SW_STRL("pipeline")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_response_class_entry_ptr, SW_STRL("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_response_class_entry_ptr, SW_STRL("set_cookie_headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_response_class_entry_ptr, SW_STRL("cookies")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http2_response_class_entry_ptr, SW_STRL("data")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

    SWOOLE_DEFINE(HTTP2_TYPE_DATA);
    SWOOLE_DEFINE(HTTP2_TYPE_HEADERS);
    SWOOLE_DEFINE(HTTP2_TYPE_PRIORITY);
    SWOOLE_DEFINE(HTTP2_TYPE_RST_STREAM);
    SWOOLE_DEFINE(HTTP2_TYPE_SETTINGS);
    SWOOLE_DEFINE(HTTP2_TYPE_PUSH_PROMISE);
    SWOOLE_DEFINE(HTTP2_TYPE_PING);
    SWOOLE_DEFINE(HTTP2_TYPE_GOAWAY);
    SWOOLE_DEFINE(HTTP2_TYPE_WINDOW_UPDATE);
    SWOOLE_DEFINE(HTTP2_TYPE_CONTINUATION);

    SWOOLE_DEFINE(HTTP2_ERROR_NO_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_PROTOCOL_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_INTERNAL_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_FLOW_CONTROL_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_SETTINGS_TIMEOUT);
    SWOOLE_DEFINE(HTTP2_ERROR_STREAM_CLOSED);
    SWOOLE_DEFINE(HTTP2_ERROR_FRAME_SIZE_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_REFUSED_STREAM);
    SWOOLE_DEFINE(HTTP2_ERROR_CANCEL);
    SWOOLE_DEFINE(HTTP2_ERROR_COMPRESSION_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_CONNECT_ERROR);
    SWOOLE_DEFINE(HTTP2_ERROR_ENHANCE_YOUR_CALM);
    SWOOLE_DEFINE(HTTP2_ERROR_INADEQUATE_SECURITY);
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
    context->coro_params = *getThis();

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

    hcc->host = estrndup(host, host_len);
    hcc->host_len = host_len;
    hcc->port = port;

    zend_update_property_long(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), type TSRMLS_CC);
    zend_update_property_stringl(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len TSRMLS_CC);
    zend_update_property_long(swoole_http2_client_coro_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);
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

static ssize_t http2_client_build_header(zval *zobject, zval *req, char *buffer TSRMLS_DC)
{
    char *date_str = NULL;
    int ret;
    int index = 0;
    int find_host = 0;

    zval *cookies = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("cookies"), 1 TSRMLS_CC);
    zval *method = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("method"), 1 TSRMLS_CC);
    zval *path = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("path"), 1 TSRMLS_CC);
    zval *headers = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("headers"), 1 TSRMLS_CC);

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

    if (headers && Z_TYPE_P(headers) == IS_ARRAY)
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
    if (cookies && Z_TYPE_P(cookies) == IS_ARRAY)
    {
        http2_add_cookie(nv, &index, cookies TSRMLS_CC);
    }

    ssize_t rv;
    size_t buflen;
    size_t i;
    size_t sum = 0;

    nghttp2_hd_deflater *deflater = hcc->deflater;
    if (!deflater)
    {
        ret = nghttp2_hd_deflate_new(&deflater, 4096);
        if (ret != 0)
        {
            swoole_php_error(E_WARNING, "nghttp2_hd_deflate_init failed with error: %s\n", nghttp2_strerror(ret));
            return SW_ERR;
        }
        hcc->deflater = deflater;
    }

    for (i = 0; i < index; ++i)
    {
        sum += nv[i].namelen + nv[i].valuelen;
    }

    buflen = nghttp2_hd_deflate_bound(deflater, nv, index);
    if (buflen > hcc->max_header_list_size)
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

    for (i = 0; i < index; ++i)
    {
        efree(nv[i].name); // free lower header name copy
    }

    if (date_str)
    {
        efree(date_str);
    }

    ret = nghttp2_hd_deflate_change_table_size(deflater, 4096);
    if (ret != 0)
    {
        swoole_php_error(E_WARNING, "nghttp2_hd_deflate_change_table_size failed with error: %s\n", nghttp2_strerror(ret));
        return SW_ERR;
    }

    return rv;
}

static void http2_client_onReceive(swClient *cli, char *buf, uint32_t _length)
{
    uint8_t type = buf[3];
    uint8_t flags = buf[4];
    uint32_t stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;
    uint32_t length = swHttp2_get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    zval *zobject = cli->object;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];

    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    if (stream_id > hcc->last_stream_id)
    {
        hcc->last_stream_id = stream_id;
    }

    uint16_t id = 0;
    uint32_t value = 0;

    switch (type)
    {
    case SW_HTTP2_TYPE_SETTINGS:
    {
        if (flags & SW_HTTP2_FLAG_ACK)
        {
            swHttp2FrameTraceLog(recv, "ACK");
            return;
        }

        while(length > 0)
        {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            swHttp2FrameTraceLog(recv, "id=%d, value=%d", id, value);
            switch (id)
            {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                swTraceLog(SW_TRACE_HTTP2, "setting: header_compression_table_max=%u.", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                hcc->max_concurrent_streams = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%u.", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                hcc->send_window = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: init_send_window=%u.", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                hcc->max_frame_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_frame_size=%u.", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                hcc->max_header_list_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_header_list_size=%u.", value);
                break;
            default:
                // disable warning and ignore it because some websites are not following http2 protocol totally
                // swWarn("unknown option[%d]: %d.", id, value);
                break;
            }
            buf += sizeof(id) + sizeof(value);
            length -= sizeof(id) + sizeof(value);
        }

        swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 0, SW_HTTP2_FLAG_ACK, stream_id);
        cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE, 0);
        return;
    }
    case SW_HTTP2_TYPE_WINDOW_UPDATE:
    {
        value = ntohl(*(uint32_t *) buf);
        swHttp2FrameTraceLog(recv, "window_size_increment=%d", value);
        if (stream_id == 0)
        {
            hcc->send_window += value;
        }
        else
        {
            http2_client_stream *stream = swHashMap_find_int(hcc->streams, stream_id);
            if (stream)
            {
                stream->send_window += value;
            }
        }
        return;
    }
    case SW_HTTP2_TYPE_PING:
    {
        swHttp2FrameTraceLog(recv, "ping");
        swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, stream_id);
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, buf + SW_HTTP2_FRAME_HEADER_SIZE, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
        cli->send(cli, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, 0);
        return;
    }
    case SW_HTTP2_TYPE_GOAWAY:
    {
        uint32_t server_last_stream_id = ntohl(*(uint32_t *) (buf));
        buf += 4;
        value = ntohl(*(uint32_t *) (buf));
        buf += 4;
        swHttp2FrameTraceLog(recv, "last_stream_id=%d, error_code=%d, opaque_data=[%.*s]", server_last_stream_id, value, length - SW_HTTP2_GOAWAY_SIZE, buf);

        // update goaway error code and error msg
        zend_update_property_long(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), value TSRMLS_CC);
        zend_update_property_stringl(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("errMsg"), buf, length - SW_HTTP2_GOAWAY_SIZE TSRMLS_CC);
        zend_update_property_long(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("serverLastStreamId"), server_last_stream_id TSRMLS_CC);

        zval* retval;
        sw_zend_call_method_with_0_params(&zobject, swoole_http2_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        if (hcc->iowait != 0)
        {
            // resume and return false
            hcc->iowait = 0;
            zval _result;
            zval *result = &_result;
            ZVAL_FALSE(result);
            php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
            int ret = coro_resume(context, result, &retval);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
        }
        return;
    }
    case SW_HTTP2_TYPE_RST_STREAM:
    {
        value = ntohl(*(uint32_t *) (buf));
        swHttp2FrameTraceLog(recv, "error_code=%d", value);

        // FIXME stream leak?
        if (hcc->iowait == 0)
        {
            return;
        }
        break;
    }
    default:
    {
        swHttp2FrameTraceLog(recv, "");
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
        if (length > 0)
        {
            if (!stream->buffer)
            {
                stream->buffer = swString_new(SW_HTTP2_DATA_BUFFER_SIZE);
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

            // now we control the connection flow only (not stream)
            // our window size is unlimited, so we don't worry about subtraction overflow
            hcc->recv_window -= length;
            stream->recv_window -= length;
            if (hcc->recv_window < (SW_HTTP2_MAX_WINDOW_SIZE / 4))
            {
                http2_client_send_window_update(cli, 0, SW_HTTP2_MAX_WINDOW_SIZE - hcc->recv_window);
                hcc->recv_window = SW_HTTP2_MAX_WINDOW_SIZE;
            }
            if (stream->recv_window < (SW_HTTP2_MAX_WINDOW_SIZE / 4))
            {
                http2_client_send_window_update(cli, stream_id, SW_HTTP2_MAX_WINDOW_SIZE - stream->recv_window);
                stream->recv_window = SW_HTTP2_MAX_WINDOW_SIZE;
            }
        }
    }

    uint8_t stream_type = stream->type;
    if (
            (type == SW_HTTP2_TYPE_DATA && stream_type == SW_HTTP2_STREAM_PIPELINE) // pipeline data frame
            || (stream_type == SW_HTTP2_STREAM_NORMAL && (flags & SW_HTTP2_FLAG_END_STREAM)) // normal end frame
            || type == SW_HTTP2_TYPE_RST_STREAM || type == SW_HTTP2_TYPE_GOAWAY // rst and goaway frame
        )
    {
        zval _zresponse = stream->_response_object;
        zval *zresponse = &_zresponse;
        zval *retval = NULL;

        if (type == SW_HTTP2_TYPE_RST_STREAM)
        {
            zend_update_property_long(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("statusCode"), -3 TSRMLS_CC);
            zend_update_property_long(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("errCode"), value TSRMLS_CC);
        }
        else if (stream_type == SW_HTTP2_STREAM_PIPELINE && !(flags & SW_HTTP2_FLAG_END_STREAM))
        {
            zend_update_property_bool(swoole_http2_response_class_entry_ptr, zresponse, ZEND_STRL("pipeline"), 1 TSRMLS_CC);
        }

        if (stream->buffer)
        {
            zend_update_property_stringl(swoole_http2_response_class_entry_ptr, stream->response_object, ZEND_STRL("data"), stream->buffer->str, stream->buffer->length TSRMLS_CC);
        }

        if (stream_type == SW_HTTP2_STREAM_NORMAL)
        {
            Z_ADDREF_P(zresponse); // dtor in del
            swHashMap_del_int(hcc->streams, stream_id);
        }
        else if (stream->buffer)
        {
            swString_clear(stream->buffer);
        }

        if (cli->timer)
        {
            swTimer_del(&SwooleG.timer, cli->timer);
            cli->timer = NULL;
        }

        if (hcc->iowait != 0)
        {
            hcc->iowait = 0;
            php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
            int ret = coro_resume(context, zresponse, &retval);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
        }

        // if not pipeline or pipeline end, response refcount--
        if (stream_type != SW_HTTP2_STREAM_PIPELINE || (flags & SW_HTTP2_FLAG_END_STREAM))
        {
            zval_ptr_dtor(zresponse);
        }
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
    if (stream->response_object)
    {
        zval_ptr_dtor(stream->response_object);
        stream->response_object = NULL;
    }
    efree(stream);
}

static uint32_t http2_client_send_request(zval *zobject, zval *req TSRMLS_DC)
{
    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;

    zval *headers = sw_zend_read_property_array(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("headers"), 1 TSRMLS_CC);
    zval *post_data = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("data"), 1 TSRMLS_CC);
    zval *pipeline = sw_zend_read_property(swoole_http2_request_class_entry_ptr, req, ZEND_STRL("pipeline"), 1 TSRMLS_CC);

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
    char* buffer = SwooleTG.buffer_stack->str;
    ssize_t n = http2_client_build_header(zobject, req, buffer + SW_HTTP2_FRAME_HEADER_SIZE TSRMLS_CC);
    if (n <= 0)
    {
        swWarn("http2_client_build_header() failed.");
        return 0;
    }

    // malloc
    http2_client_stream *stream = emalloc(sizeof(http2_client_stream));
    memset(stream, 0, sizeof(http2_client_stream));

    // init
    stream->response_object = &stream->_response_object;
    object_init_ex(stream->response_object, swoole_http2_response_class_entry_ptr);
    stream->stream_id = hcc->stream_id;
    stream->type = Z_BVAL_P(pipeline) ? SW_HTTP2_STREAM_PIPELINE : SW_HTTP2_STREAM_NORMAL;
    stream->send_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    stream->recv_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;

    // add to map
    swHashMap_add_int(hcc->streams, stream->stream_id, stream);

    if (ZVAL_IS_NULL(post_data))
    {
        //pipeline
        if (stream->type == SW_HTTP2_STREAM_PIPELINE)
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
        }
        else
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_STREAM | SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
        }
    }
    else
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, n, SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
    }

    zend_update_property_long(swoole_http2_response_class_entry_ptr, stream->response_object, ZEND_STRL("streamId"), stream->stream_id TSRMLS_CC);

    swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", STREAM#%d] length=%zd", swHttp2_get_type(SW_HTTP2_TYPE_HEADERS), stream->stream_id, n);
    cli->send(cli, buffer, n + SW_HTTP2_FRAME_HEADER_SIZE, 0);

    /**
     * send body
     */
    if (!ZVAL_IS_NULL(post_data))
    {
        char *p;
        zend_size_t len;
        smart_str formstr_s = { NULL, 0 };
        uint8_t send_flag;
        uint32_t send_len;

        int flag = stream->type == SW_HTTP2_STREAM_PIPELINE ? 0 : SW_HTTP2_FLAG_END_STREAM;
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            p = sw_http_build_query(post_data, &len, &formstr_s TSRMLS_CC);
            if (p == NULL)
            {
                swoole_php_error(E_WARNING, "http_build_query failed.");
                return 0;
            }
        }
        else
        {
            convert_to_string(post_data);
            p = Z_STRVAL_P(post_data);
            len = Z_STRLEN_P(post_data);
        }

        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream->stream_id, len);

        while (len > 0)
        {
            if (len > hcc->max_frame_size)
            {
                send_len = hcc->max_frame_size;
                send_flag = 0;
            }
            else
            {
                send_len = len;
                send_flag = flag;
            }
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, send_len, send_flag, stream->stream_id);
            if (cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0) < 0)
            {
                return 0;
            }
            if (cli->send(cli, p, send_len, 0) < 0)
            {
                return 0;
            }
            len -= send_len;
            p += send_len;
        }

        if (formstr_s.s)
        {
            smart_str_free(&formstr_s);
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
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, len);
        cli->send(cli, buffer, SW_HTTP2_FRAME_HEADER_SIZE, 0);
        cli->send(cli, formstr, len, 0);
        smart_str_free(&formstr_s);
    }
    else if (Z_TYPE_P(data) == IS_STRING)
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, Z_STRLEN_P(data), flag, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, Z_STRLEN_P(data));
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
        error:
        swoole_php_fatal_error(E_ERROR, "object is not instanceof swoole_http2_request.");
        RETURN_FALSE;
    }
    if (!instanceof_function(Z_OBJCE_P(request), swoole_http2_request_class_entry_ptr TSRMLS_CC))
    {
        goto error;
    }

    uint32_t stream_id = http2_client_send_request(getThis(), request TSRMLS_CC);
    if (stream_id == 0)
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
    if (hcc->cid != 0 && hcc->cid != sw_get_current_cid())
    {
        swoole_php_fatal_error(E_ERROR, "client has been bound to another coroutine.");
        RETURN_FALSE;
    }

    double timeout = hcc->timeout;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    php_context *context = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_CONTEXT);
    if (timeout > 0)
    {
        php_swoole_check_timer((int) (timeout * 1000));
        cli->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, http2_client_onTimeout);
    }
    hcc->cid = sw_get_current_cid();
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
    hcc->streams = swHashMap_new(8, http2_client_stream_free);
    http2_client_send_setting(cli);

    // [init]: we must set default value, server is not always send all the settings
    hcc->max_concurrent_streams = SW_HTTP2_MAX_CONCURRENT_STREAMS;
    hcc->send_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    hcc->recv_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    hcc->max_frame_size = SW_HTTP2_MAX_FRAME_SIZE;
    hcc->max_header_list_size = SW_HTTP2_MAX_HEADER_LIST_SIZE;

    hcc->iowait = 0;
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
    zval *zobject = cli->object;
    zend_update_property_bool(swoole_http2_client_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
    php_swoole_client_free(zobject, cli TSRMLS_CC);

    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    if (!hcc)
    {
        return;
    }
    hcc->client = NULL;
    if (hcc->streams)
    {
        swHashMap_free(hcc->streams);
        hcc->streams = NULL;
    }
    if (hcc->iowait == 0)
    {
        return;
    }
    hcc->cid = 0;
    hcc->iowait = 0;

    zval _result;
    zval *result = &_result;
    zval *retval = NULL;
    ZVAL_FALSE(result);
    php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void http2_client_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    php_context *ctx = tnode->data;
    zval _zobject = ctx->coro_params;
    zval *zobject = &_zobject;
    swClient *cli = swoole_get_object(zobject);
    cli->timer = NULL;

    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    hcc->iowait = 0;
    zval *result;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 0);
    zval *retval = NULL;
    int ret = coro_resume(ctx, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static PHP_METHOD(swoole_http2_client_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    zval *zobject = getThis();
    http2_client_property *hcc = swoole_get_property(zobject, HTTP2_CLIENT_CORO_PROPERTY);
    if (hcc)
    {
        if (hcc->inflater)
        {
            nghttp2_hd_inflate_del(hcc->inflater);
        }
        if (hcc->deflater)
        {
            nghttp2_hd_deflate_del(hcc->deflater);
        }
        if (hcc->host)
        {
            efree(hcc->host);
        }
        if (hcc->streams)
        {
            swHashMap_free(hcc->streams);
        }
        efree(hcc);
        swoole_set_property(zobject, HTTP2_CLIENT_CORO_PROPERTY, NULL);
    }

    php_context *context = swoole_get_property(zobject, HTTP2_CLIENT_CORO_CONTEXT);
    swoole_set_property(zobject, HTTP2_CLIENT_CORO_CONTEXT, NULL);

    swClient *cli = swoole_get_object(zobject);
    if (cli)
    {
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_http2_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    efree(context);
}

static PHP_METHOD(swoole_http2_client_coro, close)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        RETURN_FALSE;
    }

    int ret = SW_OK;
    ret = cli->close(cli);

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
    cli->onError = http2_client_onClose; // same as close
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
    hcc->iowait = 1;
    coro_yield();
}

static PHP_METHOD(swoole_http2_client_coro, stats)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    swString key;
    bzero(&key, sizeof(key));
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|s", &key.str, &key.length) == FAILURE)
    {
        return;
    }
    if (key.length > 0)
    {
        if (strcmp(key.str, "current_stream_id") == 0)
        {
           RETURN_LONG(hcc->stream_id);
        }
        else if (strcmp(key.str, "last_stream_id") == 0)
        {
           RETURN_LONG(hcc->last_stream_id);
        }
        else if (strcmp(key.str, "send_window") == 0)
        {
           RETURN_LONG(hcc->send_window);
        }
        else if (strcmp(key.str, "recv_window") == 0)
        {
           RETURN_LONG(hcc->recv_window);
        }
        else if (strcmp(key.str, "max_concurrent_streams") == 0)
        {
           RETURN_LONG(hcc->max_concurrent_streams);
        }
        else if (strcmp(key.str, "max_frame_size") == 0)
        {
           RETURN_LONG(hcc->max_frame_size);
        }
        else if (strcmp(key.str, "max_header_list_size") == 0)
        {
           RETURN_LONG(hcc->max_header_list_size);
        }
        else if (strcmp(key.str, "active_stream_num") == 0)
        {
           RETURN_LONG(hcc->streams ? swHashMap_count(hcc->streams) : 0);
        }
    }
    else
    {
        array_init(return_value);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("current_stream_id"), hcc->stream_id);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("last_stream_id"), hcc->last_stream_id);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("send_window"), hcc->send_window);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("recv_window"), hcc->recv_window);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("max_concurrent_streams"), hcc->max_concurrent_streams);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("max_frame_size"), hcc->max_frame_size);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("max_header_list_size"), hcc->max_header_list_size);
        sw_add_assoc_long_ex(return_value, ZEND_STRS("active_stream_num"), hcc->streams ? swHashMap_count(hcc->streams) : 0);
    }
}

static PHP_METHOD(swoole_http2_client_coro, isStreamExist)
{
    zend_long stream_id = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "l", &stream_id) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (stream_id < 0)
    {
        RETURN_FALSE;
    }
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    if (!hcc->client)
    {
        RETURN_FALSE;
    }
    else
    {
        if (stream_id == 0)
        {
            RETURN_TRUE;
        }
        if (!hcc->streams)
        {
            RETURN_FALSE;
        }
    }
    http2_client_stream *stream = swHashMap_find_int(hcc->streams, stream_id);
    RETURN_BOOL(stream ? 1 : 0);
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

/**
 * +-+-------------------------------------------------------------+
 * |R|                  Last-Stream-ID (31)                        |
 * +-+-------------------------------------------------------------+
 * |                      Error Code (32)                          |
 * +---------------------------------------------------------------+
 * |                  Additional Debug Data (*)                    |
 * +---------------------------------------------------------------+
 */
static PHP_METHOD(swoole_http2_client_coro, goaway)
{
    http2_client_property *hcc = swoole_get_property(getThis(), HTTP2_CLIENT_CORO_PROPERTY);
    swClient *cli = hcc->client;
    int ret;
    char* frame;
    uint8_t error_code = SW_HTTP2_ERROR_NO_ERROR;
    char* debug_data = NULL;
    long  debug_data_len = 0;

    if (!cli || !cli->socket || cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "The connection is closed.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ls", &error_code, &debug_data, &debug_data_len) == FAILURE)
    {
        return;
    }

    size_t length = SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + debug_data_len;
    frame = emalloc(length);
    bzero(frame, length);
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + debug_data_len, error_code, 0);
    *(uint32_t*) (frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(hcc->last_stream_id);
    *(uint32_t*) (frame + SW_HTTP2_FRAME_HEADER_SIZE + 4) = htonl(error_code);
    memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE, debug_data, debug_data_len);
    swTraceLog(SW_TRACE_HTTP2, "["SW_ECHO_GREEN"] Send: last-sid=%d, error-code=%d", swHttp2_get_type(SW_HTTP2_TYPE_GOAWAY), hcc->last_stream_id, error_code);

    ret = cli->send(cli, frame, length, 0);
    efree(frame);
    SW_CHECK_RETURN(ret);
}

#endif
#endif
