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

#include "php_swoole_cxx.h"
#include "swoole_http.h"

#include <iostream>

extern "C"
{
#include "ext/standard/url.h"
#include "ext/standard/sha1.h"
#include "ext/standard/php_var.h"
#include "ext/standard/php_string.h"
#include "ext/date/php_date.h"
#include "main/php_variables.h"
}

#include "websocket.h"
#include "connection.h"
#include "base64.h"
#include "thirdparty/swoole_http_parser.h"

using namespace swoole;
using namespace std;
using swoole::coroutine::Socket;

zend_class_entry *swoole_websocket_server_ce;
static zend_object_handlers swoole_websocket_server_handlers;

zend_class_entry *swoole_websocket_frame_ce;
static zend_object_handlers swoole_websocket_frame_handlers;

static zend_class_entry *swoole_websocket_closeframe_ce;
static zend_object_handlers swoole_websocket_closeframe_handlers;

static PHP_METHOD(swoole_websocket_server, push);
static PHP_METHOD(swoole_websocket_server, isEstablished);
static PHP_METHOD(swoole_websocket_server, pack);
static PHP_METHOD(swoole_websocket_server, unpack);
static PHP_METHOD(swoole_websocket_server, disconnect);

static PHP_METHOD(swoole_websocket_frame, __toString);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_push, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_disconnect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_pack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
    ZEND_ARG_INFO(0, mask)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_unpack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_isEstablished, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_frame_void, 0, 0, 0)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, push,              arginfo_swoole_websocket_server_push,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, disconnect,        arginfo_swoole_websocket_server_disconnect,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, isEstablished,     arginfo_swoole_websocket_server_isEstablished, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,              arginfo_swoole_websocket_server_pack,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,            arginfo_swoole_websocket_server_unpack,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

const zend_function_entry swoole_websocket_frame_methods[] =
{
    PHP_ME(swoole_websocket_frame, __toString,      arginfo_swoole_websocket_frame_void,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,           arginfo_swoole_websocket_server_pack,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,         arginfo_swoole_websocket_server_unpack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

static bool message_compress(const char *data, size_t length, int level);

static void php_swoole_websocket_construct_frame(zval *zframe, zend_long opcode, char *payload, size_t payload_length, zend_bool finish)
{
    if (opcode == WEBSOCKET_OPCODE_CLOSE)
    {
        object_init_ex(zframe, swoole_websocket_closeframe_ce);
        if (payload_length >= SW_WEBSOCKET_CLOSE_CODE_LEN)
        {
            // WebSocket Close code
            zend_update_property_long(
                swoole_websocket_closeframe_ce, zframe, ZEND_STRL("code"),
                (payload[0] << 8) ^ (payload[1] & 0xFF)
            );
            if (payload_length > SW_WEBSOCKET_CLOSE_CODE_LEN)
            {
                // WebSocket Close reason message
                zend_update_property_stringl(
                    swoole_websocket_closeframe_ce, zframe, ZEND_STRL("reason"),
                    payload + SW_WEBSOCKET_CLOSE_CODE_LEN, payload_length - SW_WEBSOCKET_CLOSE_CODE_LEN
                );
            }
        }
    }
    else
    {
        object_init_ex(zframe, swoole_websocket_frame_ce);
        zend_update_property_stringl(swoole_websocket_frame_ce, zframe, ZEND_STRL("data"), payload, payload_length);
    }
    zend_update_property_bool(swoole_websocket_frame_ce, zframe, ZEND_STRL("finish"), finish);
    zend_update_property_long(swoole_websocket_frame_ce, zframe, ZEND_STRL("opcode"), opcode);
}

void php_swoole_websocket_frame_unpack(swString *data, zval *zframe)
{
    swWebSocket_frame frame;

    if (data->length < sizeof(frame.header))
    {
        SwooleG.error = SW_ERROR_INVALID_PARAMS;
        ZVAL_FALSE(zframe);
        return;
    }

    swWebSocket_decode(&frame, data);
    php_swoole_websocket_construct_frame(zframe, frame.header.OPCODE, frame.payload, frame.payload_length, frame.header.FIN);
}

int php_swoole_websocket_frame_pack(swString *buffer, zval *zdata, zend_bool opcode, uint8_t flags)
{
    char *data = NULL;
    size_t length = 0;
    zend_long code = WEBSOCKET_CLOSE_NORMAL;

    if (Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_websocket_frame_ce))
    {
        zval *zframe = zdata;
        zval *ztmp = NULL;
        zdata = NULL;
        if ((ztmp = sw_zend_read_property(swoole_websocket_frame_ce, zframe, ZEND_STRL("opcode"), 0)))
        {
            opcode = zval_get_long(ztmp);
        }
        if (opcode == WEBSOCKET_OPCODE_CLOSE)
        {
            if ((ztmp = sw_zend_read_property_not_null(swoole_websocket_frame_ce, zframe, ZEND_STRL("code"), 1)))
            {
                code = zval_get_long(ztmp);
            }
            if ((ztmp = sw_zend_read_property_not_null(swoole_websocket_frame_ce, zframe, ZEND_STRL("reason"), 1)))
            {
                zdata = ztmp;
            }
        }
        if (!zdata && (ztmp = sw_zend_read_property(swoole_websocket_frame_ce, zframe, ZEND_STRL("data"), 0)))
        {
            zdata = ztmp;
        }
        if ((ztmp = sw_zend_read_property(swoole_websocket_frame_ce, zframe, ZEND_STRL("finish"), 0)))
        {
            flags = zval_is_true(ztmp) ? SW_WEBSOCKET_FLAG_FIN : 0;
        }
    }
    if (sw_unlikely(opcode > SW_WEBSOCKET_OPCODE_MAX))
    {
        php_swoole_fatal_error(E_WARNING, "the maximum value of opcode is %d", SW_WEBSOCKET_OPCODE_MAX);
        return SW_ERR;
    }
    zend::string str_zdata;
    if (zdata && !ZVAL_IS_NULL(zdata))
    {
        str_zdata = zdata;
        data = str_zdata.val();
        length = str_zdata.len();

        if ((flags & SW_WEBSOCKET_FLAG_RSV1) && message_compress(data, length, 1))
        {
            data = swoole_zlib_buffer->str;
            length = swoole_zlib_buffer->length;
        }
    }

    switch(opcode)
    {
    case WEBSOCKET_OPCODE_CLOSE:
        return swWebSocket_pack_close_frame(buffer, code, data, length, flags);
    default:
        swWebSocket_encode(buffer, data, length, opcode, flags);
    }
    return SW_OK;
}

void swoole_websocket_onOpen(swServer *serv, http_context *ctx)
{
    swConnection *conn = swWorker_get_connection(serv, ctx->fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session[%d] is closed", ctx->fd);
        return;
    }
    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, conn->server_fd, SW_SERVER_CB_onOpen);
    if (fci_cache)
    {
        zval args[2];
        args[0] = *((zval *) serv->ptr2);
        args[1] = *ctx->request.zobject;
        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, SwooleG.enable_coroutine)))
        {
            php_swoole_error(E_WARNING, "%s->onOpen handler error", ZSTR_VAL(swoole_websocket_server_ce->name));
            serv->close(serv, ctx->fd, 0);
        }
    }
}

/**
 * default onRequest callback
 */
void swoole_websocket_onRequest(http_context *ctx)
{
    const char *bad_request =
            "HTTP/1.1 400 Bad Request\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Cache-Control: must-revalidate,no-cache,no-store\r\n"
            "Content-Length: 83\r\n"
            "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n\r\n"
            "<html><body><h2>HTTP 400 Bad Request</h2><hr><i>Powered by Swoole</i></body></html>";

    ctx->send(ctx, (char *) bad_request, strlen(bad_request));
    ctx->end = 1;
    ctx->close(ctx);
    swoole_http_context_free(ctx);
}

void swoole_sha1(const char *str, int _len, unsigned char *digest)
{
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *) str, _len);
    PHP_SHA1Final(digest, &context);
}

bool swoole_websocket_handshake(http_context *ctx)
{
    char sec_buf[128];
    zval *header = ctx->request.zheader;
    HashTable *ht = Z_ARRVAL_P(header);
    zval *pData;

    if (!(pData = zend_hash_str_find(ht, ZEND_STRL("sec-websocket-key"))))
    {
        php_swoole_fatal_error(E_WARNING, "header no sec-websocket-key");
        return false;
    }

    zend::string str_pData(pData);

    char sha1_str[20];
    // sec_websocket_accept
    memcpy(sec_buf, str_pData.val(), str_pData.len());
    memcpy(sec_buf + str_pData.len(), SW_WEBSOCKET_GUID, sizeof(SW_WEBSOCKET_GUID) - 1);
    // sha1 sec_websocket_accept
    swoole_sha1(sec_buf, str_pData.len() + sizeof(SW_WEBSOCKET_GUID) - 1, (unsigned char *) sha1_str);
    // base64 encode
    int sec_len = swBase64_encode((unsigned char *) sha1_str, sizeof(sha1_str), sec_buf);

    swoole_http_response_set_header(ctx, ZEND_STRL("Upgrade"), ZEND_STRL("websocket"), false);
    swoole_http_response_set_header(ctx, ZEND_STRL("Connection"), ZEND_STRL("Upgrade"), false);
    swoole_http_response_set_header(ctx, ZEND_STRL("Sec-WebSocket-Accept"), sec_buf, sec_len, false);
    swoole_http_response_set_header(ctx, ZEND_STRL("Sec-WebSocket-Version"), ZEND_STRL(SW_WEBSOCKET_VERSION), false);

    bool websocket_compression = false;
    pData = zend_hash_str_find(ht, ZEND_STRL("sec-websocket-extensions"));
    if (pData && Z_TYPE_P(pData) == IS_STRING)
    {
        auto s = zval_get_string(pData);
        string value(s->val, s->len);
        string v = value.substr(0, value.find_first_of(';'));
        if (v.compare(string("permessage-deflate")) == 0)
        {
            websocket_compression = true;
            swoole_http_response_set_header(ctx, ZEND_STRL("Sec-Websocket-Extensions"), ZEND_STRL("permessage-deflate; server_no_context_takeover"), false);
        }
    }

    if (!ctx->co_socket)
    {
        swServer *serv = (swServer *)ctx->private_data;
        swConnection *conn = swWorker_get_connection(serv, ctx->fd);
        if (!conn)
        {
            swWarn("session[%d] is closed", ctx->fd);
            return false;
        }
        conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
        swListenPort *port = (swListenPort *) serv->connection_list[conn->server_fd].object;
        if (port && port->websocket_subprotocol)
        {
            swoole_http_response_set_header(ctx, ZEND_STRL("Sec-WebSocket-Protocol"), port->websocket_subprotocol,
                    port->websocket_subprotocol_length, false);
        }
        ctx->websocket_compression = conn->websocket_compression = websocket_compression;
    }
    else
    {
        Socket *sock = (Socket *) ctx->private_data;
        sock->open_length_check = 1;
        sock->protocol.get_package_length = swWebSocket_get_package_length;
        sock->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        ctx->websocket_compression = websocket_compression;
    }

    ctx->response.status = 101;
    ctx->upgrade = 1;

    zval retval;
    swoole_http_response_end(ctx, nullptr, &retval);
    return Z_TYPE(retval) == IS_TRUE;
}

static bool message_uncompress(const char *in, size_t in_len, swString *body)
{
    bool gzip_stream_active = false;
    z_stream gzip_stream;

    int status;
    int encoding = SW_ZLIB_ENCODING_DEFLATE;
    bool first_decompress = !gzip_stream_active;
    size_t reserved_length = body->length;

    if (!gzip_stream_active)
    {
        _retry: memset(&gzip_stream, 0, sizeof(gzip_stream));
        gzip_stream.zalloc = php_zlib_alloc;
        gzip_stream.zfree = php_zlib_free;
        // gzip_stream.total_out = 0;
        status = inflateInit2(&gzip_stream, encoding);
        if (status != Z_OK)
        {
            swWarn("inflateInit2() failed by %s", zError(status));
            return false;
        }
        gzip_stream_active = true;
    }

    gzip_stream.next_in = (Bytef *) in;
    gzip_stream.avail_in = in_len;
    gzip_stream.total_in = 0;

    while (1)
    {
        gzip_stream.avail_out = body->size - body->length;
        gzip_stream.next_out = (Bytef *) (body->str + body->length);
        status = inflate(&gzip_stream, Z_SYNC_FLUSH);
        if (status >= 0)
        {
            body->length = gzip_stream.total_out;
        }
        if (status == Z_STREAM_END || (status == Z_OK && gzip_stream.avail_in == 0))
        {
            return true;
        }
        if (status != Z_OK)
        {
            break;
        }
        if (body->length + (SW_BUFFER_SIZE_STD / 2) >= body->size)
        {
            if (swString_extend(body, body->size * 2) < 0)
            {
                status = Z_MEM_ERROR;
                break;
            }
        }
    }

    if (status == Z_DATA_ERROR && first_decompress)
    {
        first_decompress = false;
        inflateEnd(&gzip_stream);
        encoding = SW_ZLIB_ENCODING_RAW;
        body->length = reserved_length;
        goto _retry;
    }

    swWarn("http_client::decompress_response failed by %s", zError(status));
    body->length = reserved_length;
    return false;
}

static bool message_compress(const char *data, size_t length, int level)
{
    int encoding = -0xf;
    // ==== ZLIB ====
    if (level == Z_NO_COMPRESSION)
    {
        level = Z_DEFAULT_COMPRESSION;
    }
    else if (level > Z_BEST_COMPRESSION)
    {
        level = Z_BEST_COMPRESSION;
    }

    size_t memory_size = ((size_t) ((double) length * (double) 1.015)) + 10 + 8 + 4 + 1;
    if (memory_size > swoole_zlib_buffer->size)
    {
        if (swString_extend(swoole_zlib_buffer, memory_size) < 0)
        {
            return false;
        }
    }

    z_stream zstream;
    memset(&zstream, 0, sizeof(zstream));

    int status;
    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    int retval = deflateInit2(&zstream, level, Z_DEFLATED, encoding, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

    if (Z_OK == retval)
    {
        zstream.next_in = (Bytef *) data;
        zstream.next_out = (Bytef *) swoole_zlib_buffer->str;
        zstream.avail_in = length;
        zstream.avail_out = swoole_zlib_buffer->size;

        status = deflate(&zstream, Z_FINISH);
        deflateEnd(&zstream);

        if (Z_STREAM_END == status)
        {
            swoole_zlib_buffer->length = zstream.total_out;
            return true;
        }
    }
    else
    {
        swWarn("deflateInit2() failed, Error: [%d]", retval);
    }
    return false;
}

int swoole_websocket_onMessage(swServer *serv, swEventData *req)
{
    int fd = req->info.fd;
    zend_bool flags = 0;
    zend_long opcode = 0;

    zval zdata;
    char frame_header[2];

    php_swoole_get_recv_data(serv, &zdata, req, frame_header, SW_WEBSOCKET_HEADER_LEN);

    // frame info has already decoded in swWebSocket_dispatch_frame
    flags  = frame_header[0];
    opcode = frame_header[1];

    if (opcode == WEBSOCKET_OPCODE_CLOSE && !serv->listen_list->open_websocket_close_frame)
    {
        zval_ptr_dtor(&zdata);
        return SW_OK;
    }

    /**
     * RFC 7692
     */
    if (flags & SW_WEBSOCKET_FLAG_RSV1)
    {
        swString *gzip_buffer = swString_new(8192);
        if (!message_uncompress(Z_STRVAL(zdata), Z_STRLEN(zdata), gzip_buffer))
        {
            swWarn("decompress failed");
            return SW_ERROR;
        }
        zval_dtor(&zdata);
        ZVAL_STRINGL(&zdata, gzip_buffer->str, gzip_buffer->length);
        swString_free(gzip_buffer);
    }

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onMessage);
    zval args[2];

    args[0] = *(zval *) serv->ptr2;
    php_swoole_websocket_construct_frame(&args[1], opcode, Z_STRVAL(zdata), Z_STRLEN(zdata), flags & SW_WEBSOCKET_FLAG_FIN);
    zend_update_property_long(swoole_websocket_frame_ce, &args[1], ZEND_STRL("fd"), fd);

    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, SwooleG.enable_coroutine)))
    {
        php_swoole_error(E_WARNING, "%s->onMessage handler error", ZSTR_VAL(swoole_websocket_server_ce->name));
        serv->close(serv, fd, 0);
    }

    zval_ptr_dtor(&zdata);
    zval_ptr_dtor(&args[1]);

    return SW_OK;
}

int swoole_websocket_onHandshake(swServer *serv, swListenPort *port, http_context *ctx)
{
    int fd = ctx->fd;
    bool success = swoole_websocket_handshake(ctx);
    if (success)
    {
        swoole_websocket_onOpen(serv, ctx);
    }
    else
    {
        serv->close(serv, fd, 1);
    }
    if (!ctx->end)
    {
        swoole_http_context_free(ctx);
    }
    return SW_OK;
}

void php_swoole_websocket_server_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY_EX(swoole_websocket_server, "Swoole\\WebSocket\\Server", "swoole_websocket_server", NULL, swoole_websocket_server_methods, swoole_http_server);
    SW_SET_CLASS_SERIALIZABLE(swoole_websocket_server, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_websocket_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_websocket_server, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_websocket_server);
    zend_declare_property_null(swoole_websocket_server_ce, ZEND_STRL("onHandshake"), ZEND_ACC_PRIVATE);

    SW_INIT_CLASS_ENTRY(swoole_websocket_frame, "Swoole\\WebSocket\\Frame", "swoole_websocket_frame", NULL, swoole_websocket_frame_methods);
    zend_declare_property_long(swoole_websocket_frame_ce,   ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_websocket_frame_ce, ZEND_STRL("data"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_frame_ce,   ZEND_STRL("opcode"), WEBSOCKET_OPCODE_TEXT, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_websocket_frame_ce,   ZEND_STRL("finish"), 1, ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY_EX(swoole_websocket_closeframe, "Swoole\\WebSocket\\CloseFrame", "swoole_websocket_closeframe", NULL, NULL, swoole_websocket_frame);
    zend_declare_property_long(swoole_websocket_closeframe_ce,   ZEND_STRL("opcode"), WEBSOCKET_OPCODE_CLOSE, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_closeframe_ce,   ZEND_STRL("code"), WEBSOCKET_CLOSE_NORMAL, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_websocket_closeframe_ce, ZEND_STRL("reason"), "", ZEND_ACC_PUBLIC);

    /* {{{ swoole namespace */
    // status
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_CONNECTION", WEBSOCKET_STATUS_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_HANDSHAKE", WEBSOCKET_STATUS_HANDSHAKE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_ACTIVE", WEBSOCKET_STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_CLOSING", WEBSOCKET_STATUS_CLOSING);
    // all opcodes
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_CONTINUATION", WEBSOCKET_OPCODE_CONTINUATION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_CLOSE", WEBSOCKET_OPCODE_CLOSE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_PING", WEBSOCKET_OPCODE_PING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_PONG", WEBSOCKET_OPCODE_PONG);
    // close error
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_NORMAL", WEBSOCKET_CLOSE_NORMAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_GOING_AWAY", WEBSOCKET_CLOSE_GOING_AWAY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_PROTOCOL_ERROR", WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_DATA_ERROR", WEBSOCKET_CLOSE_DATA_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_STATUS_ERROR", WEBSOCKET_CLOSE_STATUS_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_ABNORMAL", WEBSOCKET_CLOSE_ABNORMAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_MESSAGE_ERROR", WEBSOCKET_CLOSE_MESSAGE_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_POLICY_ERROR", WEBSOCKET_CLOSE_POLICY_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG", WEBSOCKET_CLOSE_MESSAGE_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_EXTENSION_MISSING", WEBSOCKET_CLOSE_EXTENSION_MISSING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_SERVER_ERROR", WEBSOCKET_CLOSE_SERVER_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_TLS", WEBSOCKET_CLOSE_TLS);
    /* swoole namespace }}} */

    // status
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CONNECTION", WEBSOCKET_STATUS_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE", WEBSOCKET_STATUS_HANDSHAKE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_FRAME", WEBSOCKET_STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_ACTIVE", WEBSOCKET_STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CLOSING", WEBSOCKET_STATUS_CLOSING);
    // all opcodes
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_CONTINUATION", WEBSOCKET_OPCODE_CONTINUATION);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_CLOSE", WEBSOCKET_OPCODE_CLOSE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_PING", WEBSOCKET_OPCODE_PING);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_PONG", WEBSOCKET_OPCODE_PONG);
    // close error
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_NORMAL", WEBSOCKET_CLOSE_NORMAL);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_GOING_AWAY", WEBSOCKET_CLOSE_GOING_AWAY);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_PROTOCOL_ERROR", WEBSOCKET_CLOSE_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_DATA_ERROR", WEBSOCKET_CLOSE_DATA_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_STATUS_ERROR", WEBSOCKET_CLOSE_STATUS_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_ABNORMAL", WEBSOCKET_CLOSE_ABNORMAL);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_MESSAGE_ERROR", WEBSOCKET_CLOSE_MESSAGE_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_POLICY_ERROR", WEBSOCKET_CLOSE_POLICY_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_MESSAGE_TOO_BIG", WEBSOCKET_CLOSE_MESSAGE_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_EXTENSION_MISSING", WEBSOCKET_CLOSE_EXTENSION_MISSING);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_SERVER_ERROR", WEBSOCKET_CLOSE_SERVER_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_TLS", WEBSOCKET_CLOSE_TLS);
}

static sw_inline int swoole_websocket_server_push(swServer *serv, int fd, swString *buffer)
{
    if (sw_unlikely(fd <= 0))
    {
        php_swoole_fatal_error(E_WARNING, "fd[%d] is invalid", fd);
        return SW_ERR;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn || conn->websocket_status < WEBSOCKET_STATUS_HANDSHAKE)
    {
        SwooleG.error = SW_ERROR_WEBSOCKET_UNCONNECTED;
        php_swoole_fatal_error(E_WARNING, "the connected client of connection[%d] is not a websocket client or closed", (int ) fd);
        return SW_ERR;
    }

    int ret = serv->send(serv, fd, buffer->str, buffer->length);
    if (ret < 0 && SwooleG.error == SW_ERROR_OUTPUT_SEND_YIELD)
    {
        zval _return_value;
        zval *return_value = &_return_value;
        zval _yield_data;
        ZVAL_STRINGL(&_yield_data, buffer->str, buffer->length);
        ZVAL_FALSE(return_value);
        php_swoole_server_send_yield(serv, fd, &_yield_data, return_value);
        ret = Z_BVAL_P(return_value) ? SW_OK : SW_ERR;
    }
    return ret;
}

static sw_inline int swoole_websocket_server_close(swServer *serv, int fd, swString *buffer, uint8_t real_close)
{
    int ret = swoole_websocket_server_push(serv, fd, buffer);
    if (ret < 0 || !real_close)
    {
        return ret;
    }
    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn)
    {
        // Change status immediately to avoid double close
        conn->websocket_status = WEBSOCKET_STATUS_CLOSING;
        // Server close connection immediately
        return serv->close(serv, fd, SW_FALSE);
    }
    else
    {
        return SW_ERR;
    }
}

static PHP_METHOD(swoole_websocket_server, disconnect)
{
    zend_long fd = 0;
    zend_long code = WEBSOCKET_CLOSE_NORMAL;
    char *data = NULL;
    size_t length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|ls", &fd, &code, &data, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString_clear(swoole_http_buffer);
    if (swWebSocket_pack_close_frame(swoole_http_buffer, code, data, length, 0) < 0)
    {
        RETURN_FALSE;
    }
    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    SW_CHECK_RETURN(swoole_websocket_server_close(serv, fd, swoole_http_buffer, 1));
}

static PHP_METHOD(swoole_websocket_server, push)
{
    zend_long fd = 0;
    zval *zdata = NULL;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz|lb", &fd, &zdata, &opcode, &fin) == FAILURE)
    {
        RETURN_FALSE;
    }

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    swString_clear(swoole_http_buffer);

    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }

    uint8_t flags = swWebSocket_set_flags(1, 0, conn->websocket_compression, 0, 0);
    if (php_swoole_websocket_frame_pack(swoole_http_buffer, zdata, opcode, flags) < 0)
    {
        RETURN_FALSE;
    }

    switch (opcode)
    {
    case WEBSOCKET_OPCODE_CLOSE:
        SW_CHECK_RETURN(swoole_websocket_server_close(serv, fd, swoole_http_buffer, flags));
        break;
    default:
        SW_CHECK_RETURN(swoole_websocket_server_push(serv, fd, swoole_http_buffer));
    }
}

static PHP_METHOD(swoole_websocket_server, pack)
{
    swString *buffer = SwooleTG.buffer_stack;
    zval *zdata = NULL;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;
    zend_bool mask = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|lbb", &zdata, &opcode, &fin, &mask) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString_clear(buffer);
    uint8_t flags = swWebSocket_set_flags(fin, mask, 0, 0, 0);
    if (php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags) < 0)
    {
        RETURN_EMPTY_STRING();
    }
    else
    {
        RETVAL_STRINGL(buffer->str, buffer->length);
    }
}

static PHP_METHOD(swoole_websocket_frame, __toString)
{
    swString *buffer = SwooleTG.buffer_stack;
    zval *zdata = ZEND_THIS;
    swString_clear(buffer);
    uint8_t flags = swWebSocket_set_flags(1, 0, 0, 0, 0);
    if (php_swoole_websocket_frame_pack(buffer, zdata, WEBSOCKET_OPCODE_TEXT, flags) < 0)
    {
        RETURN_EMPTY_STRING();
    }
    else
    {
        RETVAL_STRINGL(buffer->str, buffer->length);
    }
}

static PHP_METHOD(swoole_websocket_server, unpack)
{
    swString buffer;
    bzero(&buffer, sizeof(buffer));

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &buffer.str, &buffer.length) == FAILURE)
    {
        RETURN_FALSE;
    }

    php_swoole_websocket_frame_unpack(&buffer, return_value);
}

static PHP_METHOD(swoole_websocket_server, isEstablished)
{
    zend_long fd;

    swServer *serv = (swServer *) swoole_get_object(ZEND_THIS);
    if (sw_unlikely(!serv->gs->start))
    {
        php_error_docref(NULL, E_WARNING, "the server is not running");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &fd) == FAILURE)
    {
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(serv, fd);
    //not isEstablished
    if (!conn || conn->active == 0 || conn->closed || conn->websocket_status < WEBSOCKET_STATUS_ACTIVE)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}
