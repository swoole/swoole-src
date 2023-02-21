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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_http_server.h"

SW_EXTERN_C_BEGIN
#include "ext/standard/sha1.h"
SW_EXTERN_C_END

#include "swoole_base64.h"

using swoole::Connection;
using swoole::ListenPort;
using swoole::RecvData;
using swoole::Server;
using swoole::SessionId;
using swoole::String;
using swoole::coroutine::Socket;

using HttpContext = swoole::http::Context;

namespace WebSocket = swoole::websocket;

zend_class_entry *swoole_websocket_server_ce;
static zend_object_handlers swoole_websocket_server_handlers;

zend_class_entry *swoole_websocket_frame_ce;
static zend_object_handlers swoole_websocket_frame_handlers;

static zend_class_entry *swoole_websocket_closeframe_ce;
static zend_object_handlers swoole_websocket_closeframe_handlers;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_websocket_server, push);
static PHP_METHOD(swoole_websocket_server, isEstablished);
static PHP_METHOD(swoole_websocket_server, pack);
static PHP_METHOD(swoole_websocket_server, unpack);
static PHP_METHOD(swoole_websocket_server, disconnect);

static PHP_METHOD(swoole_websocket_frame, __toString);
SW_EXTERN_C_END

// clang-format off

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_push, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_disconnect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_pack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_unpack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_isEstablished, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_frame_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_websocket_frame___toString, 0, 0, IS_STRING, 0)
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
    PHP_ME(swoole_websocket_frame, __toString,      arginfo_swoole_websocket_frame___toString,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,           arginfo_swoole_websocket_server_pack,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,         arginfo_swoole_websocket_server_unpack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

#ifdef SW_HAVE_ZLIB
static bool websocket_message_compress(String *buffer, const char *data, size_t length, int level);
static bool websocket_message_uncompress(String *buffer, const char *in, size_t in_len);
#endif

static void php_swoole_websocket_construct_frame(zval *zframe, zend_long opcode, zval *zpayload, uint8_t flags) {
    if (opcode == WebSocket::OPCODE_CLOSE) {
        const char *payload = Z_STRVAL_P(zpayload);
        size_t payload_length = Z_STRLEN_P(zpayload);
        object_init_ex(zframe, swoole_websocket_closeframe_ce);
        if (payload_length >= SW_WEBSOCKET_CLOSE_CODE_LEN) {
            // WebSocket Close code
            zend_update_property_long(swoole_websocket_closeframe_ce,
                                      SW_Z8_OBJ_P(zframe),
                                      ZEND_STRL("code"),
                                      (payload[0] << 8) ^ (payload[1] & 0xFF));
            if (payload_length > SW_WEBSOCKET_CLOSE_CODE_LEN) {
                // WebSocket Close reason message
                zend_update_property_stringl(swoole_websocket_closeframe_ce,
                                             SW_Z8_OBJ_P(zframe),
                                             ZEND_STRL("reason"),
                                             payload + SW_WEBSOCKET_CLOSE_CODE_LEN,
                                             payload_length - SW_WEBSOCKET_CLOSE_CODE_LEN);
            }
        }
    } else {
        object_init_ex(zframe, swoole_websocket_frame_ce);
        zend_update_property(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("data"), zpayload);
    }
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("opcode"), opcode);
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("flags"), flags);
    /* BC */
    zend_update_property_bool(
        swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("finish"), flags & WebSocket::FLAG_FIN);
}

void php_swoole_websocket_frame_unpack_ex(String *data, zval *zframe, uchar uncompress) {
    WebSocket::Frame frame;
    zval zpayload;
    uint8_t flags;

    if (data->length < sizeof(frame.header)) {
        swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
        ZVAL_FALSE(zframe);
        return;
    }

    if (!WebSocket::decode(&frame, data)) {
        swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
        ZVAL_FALSE(zframe);
        return;
    }

    flags = WebSocket::get_flags(&frame);
#ifdef SW_HAVE_ZLIB
    if (uncompress && frame.header.RSV1) {
        swoole_zlib_buffer->clear();
        if (!websocket_message_uncompress(swoole_zlib_buffer, frame.payload, frame.payload_length)) {
            swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
            ZVAL_FALSE(zframe);
            return;
        }
        frame.payload = swoole_zlib_buffer->str;
        frame.payload_length = swoole_zlib_buffer->length;
        flags ^= (WebSocket::FLAG_RSV1 | WebSocket::FLAG_COMPRESS);
    }
#endif
    /* TODO: optimize memory copy */
    ZVAL_STRINGL(&zpayload, frame.payload, frame.payload_length);
    php_swoole_websocket_construct_frame(zframe, frame.header.OPCODE, &zpayload, flags);
    zval_ptr_dtor(&zpayload);
}

void php_swoole_websocket_frame_unpack(String *data, zval *zframe) {
    return php_swoole_websocket_frame_unpack_ex(data, zframe, 0);
}

static sw_inline int php_swoole_websocket_frame_pack_ex(String *buffer,
                                                        zval *zdata,
                                                        zend_long opcode,
                                                        zend_long code,
                                                        uint8_t flags,
                                                        zend_bool mask,
                                                        zend_bool allow_compress) {
    char *data = nullptr;
    size_t length = 0;

    if (sw_unlikely(opcode > SW_WEBSOCKET_OPCODE_MAX)) {
        php_swoole_fatal_error(E_WARNING, "the maximum value of opcode is %d", SW_WEBSOCKET_OPCODE_MAX);
        return SW_ERR;
    }

    zend::String str_zdata;
    if (zdata && !ZVAL_IS_NULL(zdata)) {
        str_zdata = zdata;
        data = str_zdata.val();
        length = str_zdata.len();
    }

    if (mask) {
        flags |= WebSocket::FLAG_MASK;
    }

#ifdef SW_HAVE_ZLIB
    if (flags & WebSocket::FLAG_COMPRESS) {
        if (!allow_compress) {
            flags ^= WebSocket::FLAG_COMPRESS;
        } else if (length > 0) {
            swoole_zlib_buffer->clear();
            if (websocket_message_compress(swoole_zlib_buffer, data, length, Z_DEFAULT_COMPRESSION)) {
                data = swoole_zlib_buffer->str;
                length = swoole_zlib_buffer->length;
                flags |= WebSocket::FLAG_RSV1;
            }
        }
    }
#endif

    switch (opcode) {
    case WebSocket::OPCODE_CLOSE:
        return WebSocket::pack_close_frame(buffer, code, data, length, flags);
    default:
        return WebSocket::encode(buffer, data, length, opcode, flags) ? SW_OK : SW_ERR;
    }
}

int php_swoole_websocket_frame_pack_ex(
    String *buffer, zval *zdata, zend_long opcode, uint8_t flags, zend_bool mask, zend_bool allow_compress) {
    return php_swoole_websocket_frame_pack_ex(
        buffer, zdata, opcode, WebSocket::CLOSE_NORMAL, flags, mask, allow_compress);
}

int php_swoole_websocket_frame_object_pack_ex(String *buffer, zval *zdata, zend_bool mask, zend_bool allow_compress) {
    zval *zframe = zdata;
    zend_long opcode = WebSocket::OPCODE_TEXT;
    zend_long code = WebSocket::CLOSE_NORMAL;
    zend_long flags = WebSocket::FLAG_FIN;
    zval *ztmp = nullptr;

    zdata = nullptr;
    if ((ztmp = sw_zend_read_property_ex(swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_OPCODE), 1))) {
        opcode = zval_get_long(ztmp);
    }
    if (opcode == WebSocket::OPCODE_CLOSE) {
        if ((ztmp = sw_zend_read_property_not_null_ex(
                 swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_CODE), 1))) {
            code = zval_get_long(ztmp);
        }
        if ((ztmp = sw_zend_read_property_not_null_ex(
                 swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_REASON), 1))) {
            zdata = ztmp;
        }
    }
    if (!zdata &&
        (ztmp = sw_zend_read_property_ex(swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_DATA), 1))) {
        zdata = ztmp;
    }
    if ((ztmp = sw_zend_read_property_ex(swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_FLAGS), 1))) {
        flags = zval_get_long(ztmp) & WebSocket::FLAGS_ALL;
    }
    if ((ztmp = sw_zend_read_property_not_null_ex(
             swoole_websocket_frame_ce, zframe, SW_ZSTR_KNOWN(SW_ZEND_STR_FINISH), 1))) {
        if (zval_is_true(ztmp)) {
            flags |= WebSocket::FLAG_FIN;
        } else {
            flags &= ~WebSocket::FLAG_FIN;
        }
    }

    return php_swoole_websocket_frame_pack_ex(
        buffer, zdata, opcode, code, flags & WebSocket::FLAGS_ALL, mask, allow_compress);
}

void swoole_websocket_onOpen(Server *serv, HttpContext *ctx) {
    Connection *conn = serv->get_connection_by_session_id(ctx->fd);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session[%ld] is closed", ctx->fd);
        return;
    }
    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, conn->server_fd, SW_SERVER_CB_onOpen);
    if (fci_cache) {
        zval args[2];
        args[0] = *((zval *) serv->private_data_2);
        args[1] = *ctx->request.zobject;
        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, serv->is_enable_coroutine()))) {
            php_swoole_error(E_WARNING, "%s->onOpen handler error", ZSTR_VAL(swoole_websocket_server_ce->name));
            serv->close(ctx->fd, false);
        }
    }
}

/**
 * default onRequest callback
 */
void swoole_websocket_onRequest(HttpContext *ctx) {
    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n"
                              "Connection: close\r\n"
                              "Content-Type: text/html; charset=UTF-8\r\n"
                              "Cache-Control: must-revalidate,no-cache,no-store\r\n"
                              "Content-Length: 83\r\n"
                              "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n\r\n"
                              "<html><body><h2>HTTP 400 Bad Request</h2><hr><i>Powered by Swoole</i></body></html>";

    ctx->send(ctx, (char *) bad_request, strlen(bad_request));
    ctx->end_ = 1;
    ctx->close(ctx);
}

void php_swoole_sha1(const char *str, int _len, unsigned char *digest) {
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *) str, _len);
    PHP_SHA1Final(digest, &context);
}

bool swoole_websocket_handshake(HttpContext *ctx) {
    char sec_buf[128];
    zval *header = ctx->request.zheader;
    HashTable *ht = Z_ARRVAL_P(header);
    zval *pData;
    zval retval;

    if (!(pData = zend_hash_str_find(ht, ZEND_STRL("sec-websocket-key")))) {
    _bad_request:
        ctx->response.status = SW_HTTP_BAD_REQUEST;
        ctx->end(nullptr, &retval);
        return false;
    }

    zend::String str_pData(pData);

    if (str_pData.len() != BASE64_ENCODE_OUT_SIZE(SW_WEBSOCKET_SEC_KEY_LEN)) {
        goto _bad_request;
    }

    char sha1_str[20];
    // sec_websocket_accept
    memcpy(sec_buf, str_pData.val(), str_pData.len());
    memcpy(sec_buf + str_pData.len(), SW_WEBSOCKET_GUID, sizeof(SW_WEBSOCKET_GUID) - 1);
    // sha1 sec_websocket_accept
    php_swoole_sha1(sec_buf, str_pData.len() + sizeof(SW_WEBSOCKET_GUID) - 1, (unsigned char *) sha1_str);
    // base64 encode
    int sec_len = swoole::base64_encode((unsigned char *) sha1_str, sizeof(sha1_str), sec_buf);

    ctx->set_header(ZEND_STRL("Upgrade"), ZEND_STRL("websocket"), false);
    ctx->set_header(ZEND_STRL("Connection"), ZEND_STRL("Upgrade"), false);
    ctx->set_header(ZEND_STRL("Sec-WebSocket-Accept"), sec_buf, sec_len, false);
    ctx->set_header(ZEND_STRL("Sec-WebSocket-Version"), ZEND_STRL(SW_WEBSOCKET_VERSION), false);

#ifdef SW_HAVE_ZLIB
    bool enable_websocket_compression = true;
    bool websocket_compression = false;
#endif
    Server *serv = nullptr;
    Connection *conn = nullptr;

    if (!ctx->co_socket) {
        serv = (Server *) ctx->private_data;
        conn = serv->get_connection_by_session_id(ctx->fd);
        if (!conn) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session[%ld] is closed", ctx->fd);
            return false;
        }
#ifdef SW_HAVE_ZLIB
        enable_websocket_compression = serv->websocket_compression;
#endif
    }
#ifdef SW_HAVE_ZLIB
    else {
        enable_websocket_compression = ctx->websocket_compression;
    }
#endif

#ifdef SW_HAVE_ZLIB
    if (enable_websocket_compression && (pData = zend_hash_str_find(ht, ZEND_STRL("sec-websocket-extensions"))) &&
        Z_TYPE_P(pData) == IS_STRING) {
        std::string value(Z_STRVAL_P(pData), Z_STRLEN_P(pData));
        if (value.substr(0, value.find_first_of(';')) == "permessage-deflate") {
            websocket_compression = true;
            ctx->set_header(ZEND_STRL("Sec-Websocket-Extensions"), ZEND_STRL(SW_WEBSOCKET_EXTENSION_DEFLATE), false);
        }
    }
#endif

    if (conn) {
        conn->websocket_status = WebSocket::STATUS_ACTIVE;
        ListenPort *port = serv->get_port_by_server_fd(conn->server_fd);
        if (port && !port->websocket_subprotocol.empty()) {
            ctx->set_header(ZEND_STRL("Sec-WebSocket-Protocol"),
                            port->websocket_subprotocol.c_str(),
                            port->websocket_subprotocol.length(),
                            false);
        }
#ifdef SW_HAVE_ZLIB
        ctx->websocket_compression = conn->websocket_compression = websocket_compression;
#endif
    } else {
        Socket *sock = (Socket *) ctx->private_data;
        sock->open_length_check = 1;
        sock->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        sock->protocol.package_length_offset = 0;
        sock->protocol.package_body_offset = 0;
        sock->protocol.get_package_length = WebSocket::get_package_length;
#ifdef SW_HAVE_ZLIB
        ctx->websocket_compression = websocket_compression;
#endif
    }

    ctx->response.status = SW_HTTP_SWITCHING_PROTOCOLS;
    ctx->upgrade = 1;

    ctx->end(nullptr, &retval);
    return Z_TYPE(retval) == IS_TRUE;
}

#ifdef SW_HAVE_ZLIB
static bool websocket_message_uncompress(String *buffer, const char *in, size_t in_len) {
    z_stream zstream;
    int status;
    bool ret = false;

    memset(&zstream, 0, sizeof(zstream));
    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;
    // gzip_stream.total_out = 0;
    status = inflateInit2(&zstream, SW_ZLIB_ENCODING_RAW);
    if (status != Z_OK) {
        swoole_warning("inflateInit2() failed by %s", zError(status));
        return false;
    }

    zstream.next_in = (Bytef *) in;
    zstream.avail_in = in_len;
    zstream.total_in = 0;

    while (1) {
        zstream.avail_out = buffer->size - buffer->length;
        zstream.next_out = (Bytef *) (buffer->str + buffer->length);
        status = inflate(&zstream, Z_SYNC_FLUSH);
        if (status >= 0) {
            buffer->length = zstream.total_out;
        }
        if (status == Z_STREAM_END || (status == Z_OK && zstream.avail_in == 0)) {
            ret = true;
            break;
        }
        if (status != Z_OK) {
            break;
        }
        if (buffer->length + (SW_BUFFER_SIZE_STD / 2) >= buffer->size) {
            if (!buffer->extend()) {
                status = Z_MEM_ERROR;
                break;
            }
        }
    }
    inflateEnd(&zstream);

    if (!ret) {
        swoole_warning("inflate() failed, Error: %s[%d]", zError(status), status);
        return false;
    }
    return true;
}

static bool websocket_message_compress(String *buffer, const char *data, size_t length, int level) {
    // ==== ZLIB ====
    if (level == Z_NO_COMPRESSION) {
        level = Z_DEFAULT_COMPRESSION;
    } else if (level > Z_BEST_COMPRESSION) {
        level = Z_BEST_COMPRESSION;
    }

    z_stream zstream = {};
    int status;

    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    status = deflateInit2(&zstream, level, Z_DEFLATED, SW_ZLIB_ENCODING_RAW, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        swoole_warning("deflateInit2() failed, Error: [%d]", status);
        return false;
    }

    zstream.next_in = (Bytef *) data;
    zstream.avail_in = length;
    zstream.next_out = (Bytef *) buffer->str;

    size_t max_length = deflateBound(&zstream, length);
    if (max_length > buffer->size) {
        if (!buffer->extend(max_length)) {
            return false;
        }
    }

    size_t bytes_written = 0;
    uchar in_sync_flush;
    int result;

    do {
        size_t write_remaining;

        if (zstream.avail_out == 0) {
            size_t write_position;

            zstream.avail_out = max_length;
            write_position = buffer->length;
            buffer->length = max_length;
            zstream.next_out = (Bytef *) buffer->str + write_position;

            /* Use a fixed value for buffer increments */
            max_length = 4096;
        }

        write_remaining = buffer->length - bytes_written;
        in_sync_flush = zstream.avail_in == 0;
        result = deflate(&zstream, in_sync_flush ? Z_SYNC_FLUSH : Z_NO_FLUSH);
        bytes_written += write_remaining - zstream.avail_out;
    } while (result == Z_OK);

    deflateEnd(&zstream);

    if (result != Z_BUF_ERROR || bytes_written < 4) {
        swoole_warning("Failed to compress outgoing frame");
        return false;
    }

    if (status != Z_OK) {
        swoole_warning("deflate() failed, Error: [%d]", status);
        return false;
    }

    buffer->length = bytes_written - 4;

    return true;
}
#endif

int swoole_websocket_onMessage(Server *serv, RecvData *req) {
    SessionId fd = req->info.fd;
    uchar flags = 0;
    zend_long opcode = 0;
    auto port = serv->get_port_by_session_id(fd);
    if (!port) {
        return SW_ERR;
    }

    zval zdata;
    char frame_header[2];
    memcpy(frame_header, &req->info.ext_flags, sizeof(frame_header));

    php_swoole_get_recv_data(serv, &zdata, req);

    // frame info has already decoded in websocket::dispatch_frame
    flags = frame_header[0];
    opcode = frame_header[1];

    if ((opcode == WebSocket::OPCODE_CLOSE && !port->open_websocket_close_frame) ||
        (opcode == WebSocket::OPCODE_PING && !port->open_websocket_ping_frame) ||
        (opcode == WebSocket::OPCODE_PONG && !port->open_websocket_pong_frame)) {
        if (opcode == WebSocket::OPCODE_PING) {
            String send_frame = {};
            char buf[SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_CLOSE_CODE_LEN + SW_WEBSOCKET_CLOSE_REASON_MAX_LEN];
            send_frame.str = buf;
            send_frame.size = sizeof(buf);
            WebSocket::encode(&send_frame, req->data, req->info.len, WebSocket::OPCODE_PONG, WebSocket::FLAG_FIN);
            serv->send(fd, send_frame.str, send_frame.length);
        }
        zval_ptr_dtor(&zdata);
        return SW_OK;
    }

#ifdef SW_HAVE_ZLIB
    /**
     * RFC 7692
     */
    if (serv->websocket_compression && (flags & WebSocket::FLAG_RSV1)) {
        swoole_zlib_buffer->clear();
        if (!websocket_message_uncompress(swoole_zlib_buffer, Z_STRVAL(zdata), Z_STRLEN(zdata))) {
            zval_ptr_dtor(&zdata);
            return SW_OK;
        }
        zval_ptr_dtor(&zdata);
        ZVAL_STRINGL(&zdata, swoole_zlib_buffer->str, swoole_zlib_buffer->length);
        flags ^= (WebSocket::FLAG_RSV1 | WebSocket::FLAG_COMPRESS);
    }
#endif

    zend_fcall_info_cache *fci_cache =
        php_swoole_server_get_fci_cache(serv, req->info.server_fd, SW_SERVER_CB_onMessage);
    zval args[2];

    args[0] = *(zval *) serv->private_data_2;
    php_swoole_websocket_construct_frame(&args[1], opcode, &zdata, flags);
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(&args[1]), ZEND_STRL("fd"), fd);

    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onMessage handler error", ZSTR_VAL(swoole_websocket_server_ce->name));
        serv->close(fd, false);
    }

    zval_ptr_dtor(&zdata);
    zval_ptr_dtor(&args[1]);

    return SW_OK;
}

int swoole_websocket_onHandshake(Server *serv, ListenPort *port, HttpContext *ctx) {
    SessionId fd = ctx->fd;
    bool success = swoole_websocket_handshake(ctx);
    if (success) {
        swoole_websocket_onOpen(serv, ctx);
    } else {
        serv->close(fd, true);
    }
    return SW_OK;
}

void php_swoole_websocket_server_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_EX(swoole_websocket_server,
                           "Swoole\\WebSocket\\Server",
                           "swoole_websocket_server",
                           nullptr,
                           swoole_websocket_server_methods,
                           swoole_http_server);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_websocket_server);
    SW_SET_CLASS_CLONEABLE(swoole_websocket_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_websocket_server, sw_zend_class_unset_property_deny);

    SW_INIT_CLASS_ENTRY(swoole_websocket_frame,
                        "Swoole\\WebSocket\\Frame",
                        "swoole_websocket_frame",
                        nullptr,
                        swoole_websocket_frame_methods);
    #if PHP_VERSION_ID >= 80000
        zend_class_implements(swoole_websocket_frame_ce, 1, zend_ce_stringable);
    #endif
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_websocket_frame_ce, ZEND_STRL("data"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("opcode"), WebSocket::OPCODE_TEXT, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("flags"), WebSocket::FLAG_FIN, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_websocket_frame_ce, ZEND_STRL("finish"), ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY_EX(swoole_websocket_closeframe,
                           "Swoole\\WebSocket\\CloseFrame",
                           "swoole_websocket_closeframe",
                           nullptr,
                           nullptr,
                           swoole_websocket_frame);
    zend_declare_property_long(
        swoole_websocket_closeframe_ce, ZEND_STRL("opcode"), WebSocket::OPCODE_CLOSE, ZEND_ACC_PUBLIC);
    zend_declare_property_long(
        swoole_websocket_closeframe_ce, ZEND_STRL("code"), WebSocket::CLOSE_NORMAL, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_websocket_closeframe_ce, ZEND_STRL("reason"), "", ZEND_ACC_PUBLIC);

    /* {{{ swoole namespace */
    // status
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_CONNECTION", WebSocket::STATUS_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_HANDSHAKE", WebSocket::STATUS_HANDSHAKE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_ACTIVE", WebSocket::STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_STATUS_CLOSING", WebSocket::STATUS_CLOSING);
    // all opcodes
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_CONTINUATION", WebSocket::OPCODE_CONTINUATION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_TEXT", WebSocket::OPCODE_TEXT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_BINARY", WebSocket::OPCODE_BINARY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_CLOSE", WebSocket::OPCODE_CLOSE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_PING", WebSocket::OPCODE_PING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_OPCODE_PONG", WebSocket::OPCODE_PONG);
    // flags
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_FIN", WebSocket::FLAG_FIN);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_RSV1", WebSocket::FLAG_RSV1);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_RSV2", WebSocket::FLAG_RSV2);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_RSV3", WebSocket::FLAG_RSV3);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_MASK", WebSocket::FLAG_MASK);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_FLAG_COMPRESS", WebSocket::FLAG_COMPRESS);
    // close error
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_NORMAL", WebSocket::CLOSE_NORMAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_GOING_AWAY", WebSocket::CLOSE_GOING_AWAY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_PROTOCOL_ERROR", WebSocket::CLOSE_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_DATA_ERROR", WebSocket::CLOSE_DATA_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_STATUS_ERROR", WebSocket::CLOSE_STATUS_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_ABNORMAL", WebSocket::CLOSE_ABNORMAL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_MESSAGE_ERROR", WebSocket::CLOSE_MESSAGE_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_POLICY_ERROR", WebSocket::CLOSE_POLICY_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_MESSAGE_TOO_BIG", WebSocket::CLOSE_MESSAGE_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_EXTENSION_MISSING", WebSocket::CLOSE_EXTENSION_MISSING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_SERVER_ERROR", WebSocket::CLOSE_SERVER_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_TLS", WebSocket::CLOSE_TLS);
    /* swoole namespace }}} */

    /* BC */
    // status
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CONNECTION", WebSocket::STATUS_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE", WebSocket::STATUS_HANDSHAKE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_FRAME", WebSocket::STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_ACTIVE", WebSocket::STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CLOSING", WebSocket::STATUS_CLOSING);
    // all opcodes
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_CONTINUATION", WebSocket::OPCODE_CONTINUATION);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WebSocket::OPCODE_TEXT);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WebSocket::OPCODE_BINARY);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_CLOSE", WebSocket::OPCODE_CLOSE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_PING", WebSocket::OPCODE_PING);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_PONG", WebSocket::OPCODE_PONG);
    // close error
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_NORMAL", WebSocket::CLOSE_NORMAL);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_GOING_AWAY", WebSocket::CLOSE_GOING_AWAY);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_PROTOCOL_ERROR", WebSocket::CLOSE_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_DATA_ERROR", WebSocket::CLOSE_DATA_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_STATUS_ERROR", WebSocket::CLOSE_STATUS_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_ABNORMAL", WebSocket::CLOSE_ABNORMAL);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_MESSAGE_ERROR", WebSocket::CLOSE_MESSAGE_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_POLICY_ERROR", WebSocket::CLOSE_POLICY_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_MESSAGE_TOO_BIG", WebSocket::CLOSE_MESSAGE_TOO_BIG);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_EXTENSION_MISSING", WebSocket::CLOSE_EXTENSION_MISSING);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_SERVER_ERROR", WebSocket::CLOSE_SERVER_ERROR);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_TLS", WebSocket::CLOSE_TLS);
}

static sw_inline bool swoole_websocket_server_push(Server *serv, SessionId fd, String *buffer) {
    if (sw_unlikely(fd <= 0)) {
        php_swoole_fatal_error(E_WARNING, "fd[%ld] is invalid", fd);
        return false;
    }

    Connection *conn = serv->get_connection_by_session_id(fd);
    if (!conn || conn->websocket_status < WebSocket::STATUS_HANDSHAKE) {
        swoole_set_last_error(SW_ERROR_WEBSOCKET_UNCONNECTED);
        php_swoole_fatal_error(
            E_WARNING, "the connected client of connection[%ld] is not a websocket client or closed", fd);
        return false;
    }

    bool ret = serv->send(fd, buffer->str, buffer->length);
    if (!ret && swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD) {
        zval _return_value;
        zval *return_value = &_return_value;
        zval _yield_data;
        ZVAL_STRINGL(&_yield_data, buffer->str, buffer->length);
        ZVAL_FALSE(return_value);
        php_swoole_server_send_yield(serv, fd, &_yield_data, return_value);
        ret = Z_BVAL_P(return_value);
        zval_ptr_dtor(&_yield_data);
    }
    return ret;
}

static sw_inline bool swoole_websocket_server_close(Server *serv, SessionId fd, String *buffer, bool real_close) {
    bool ret = swoole_websocket_server_push(serv, fd, buffer);
    if (!ret || !real_close) {
        return ret;
    }
    Connection *conn = serv->get_connection_by_session_id(fd);
    if (conn) {
        // Change status immediately to avoid double close
        conn->websocket_status = WebSocket::STATUS_CLOSING;
        // Server close connection immediately
        return serv->close(fd, false);
    } else {
        return false;
    }
}

static PHP_METHOD(swoole_websocket_server, disconnect) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd = 0;
    zend_long code = WebSocket::CLOSE_NORMAL;
    char *data = nullptr;
    size_t length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|ls", &fd, &code, &data, &length) == FAILURE) {
        RETURN_FALSE;
    }
    swoole_http_buffer->clear();
    if (WebSocket::pack_close_frame(swoole_http_buffer, code, data, length, 0) < 0) {
        RETURN_FALSE;
    }
    RETURN_BOOL(swoole_websocket_server_close(serv, fd, swoole_http_buffer, 1));
}

static PHP_METHOD(swoole_websocket_server, push) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd = 0;
    zval *zdata = nullptr;
    zend_long opcode = WebSocket::OPCODE_TEXT;
    zval *zflags = nullptr;
    zend_long flags = WebSocket::FLAG_FIN;
#ifdef SW_HAVE_ZLIB
    zend_bool allow_compress = 0;
#endif

    ZEND_PARSE_PARAMETERS_START(2, 4)
    Z_PARAM_LONG(fd)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(opcode)
    Z_PARAM_ZVAL_EX(zflags, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zflags != nullptr) {
        flags = zval_get_long(zflags);
    }

#ifdef SW_HAVE_ZLIB
    Connection *conn = serv->get_connection_verify(fd);
    if (!conn) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        php_swoole_fatal_error(E_WARNING, "session#" ZEND_LONG_FMT " does not exists", fd);
        RETURN_FALSE;
    }
    allow_compress = conn->websocket_compression;
#endif

    swoole_http_buffer->clear();
    if (php_swoole_websocket_frame_is_object(zdata)) {
        if (php_swoole_websocket_frame_object_pack(swoole_http_buffer, zdata, 0, allow_compress) < 0) {
            swoole_set_last_error(SW_ERROR_WEBSOCKET_PACK_FAILED);
            RETURN_FALSE;
        }
    } else {
        if (php_swoole_websocket_frame_pack(
                swoole_http_buffer, zdata, opcode, flags & WebSocket::FLAGS_ALL, 0, allow_compress) < 0) {
            swoole_set_last_error(SW_ERROR_WEBSOCKET_PACK_FAILED);
            RETURN_FALSE;
        }
    }

    switch (opcode) {
    case WebSocket::OPCODE_CLOSE:
        RETURN_BOOL(swoole_websocket_server_close(serv, fd, swoole_http_buffer, flags & WebSocket::FLAG_FIN));
        break;
    default:
        RETURN_BOOL(swoole_websocket_server_push(serv, fd, swoole_http_buffer));
    }
}

static PHP_METHOD(swoole_websocket_server, pack) {
    String *buffer = sw_tg_buffer();
    zval *zdata;
    zend_long opcode = WebSocket::OPCODE_TEXT;
    zval *zflags = nullptr;
    zend_long flags = WebSocket::FLAG_FIN;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(opcode)
    Z_PARAM_ZVAL_EX(zflags, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zflags != nullptr) {
        flags = zval_get_long(zflags);
    }

    buffer->clear();
    if (php_swoole_websocket_frame_is_object(zdata)) {
        if (php_swoole_websocket_frame_object_pack(buffer, zdata, 0, 1) < 0) {
            RETURN_EMPTY_STRING();
        }
    } else {
        if (php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags & WebSocket::FLAGS_ALL, 0, 1) < 0) {
            RETURN_EMPTY_STRING();
        }
    }
    RETURN_STRINGL(buffer->str, buffer->length);
}

static PHP_METHOD(swoole_websocket_frame, __toString) {
    String *buffer = sw_tg_buffer();
    buffer->clear();

    if (php_swoole_websocket_frame_object_pack(buffer, ZEND_THIS, 0, 1) < 0) {
        RETURN_EMPTY_STRING();
    }
    RETURN_STRINGL(buffer->str, buffer->length);
}

static PHP_METHOD(swoole_websocket_server, unpack) {
    String buffer = {};

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &buffer.str, &buffer.length) == FAILURE) {
        RETURN_FALSE;
    }

    php_swoole_websocket_frame_unpack(&buffer, return_value);
}

static PHP_METHOD(swoole_websocket_server, isEstablished) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long session_id;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &session_id) == FAILURE) {
        RETURN_FALSE;
    }

    Connection *conn = serv->get_connection_verify(session_id);
    // not isEstablished
    if (!conn || conn->closed || conn->websocket_status < WebSocket::STATUS_ACTIVE) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}
