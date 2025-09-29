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
#include "php_swoole_websocket.h"

SW_EXTERN_C_BEGIN
#include "ext/standard/sha1.h"
#include "stubs/php_swoole_websocket_arginfo.h"
SW_EXTERN_C_END

#include "swoole_base64.h"

using swoole::Connection;
using swoole::ListenPort;
using swoole::make_string;
using swoole::RecvData;
using swoole::Server;
using swoole::SessionId;
using swoole::String;
using swoole::WebSocketSettings;
using swoole::coroutine::Socket;
using swoole::websocket::Frame;
using swoole::websocket::FrameObject;

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
static PHP_METHOD(swoole_websocket_server, ping);

static PHP_METHOD(swoole_websocket_frame, __toString);
SW_EXTERN_C_END

// clang-format off
const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, push,          arginfo_class_Swoole_WebSocket_Server_push,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, disconnect,    arginfo_class_Swoole_WebSocket_Server_disconnect,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, ping,          arginfo_class_Swoole_WebSocket_Server_ping,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, isEstablished, arginfo_class_Swoole_WebSocket_Server_isEstablished, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,          arginfo_class_Swoole_WebSocket_Server_pack,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,        arginfo_class_Swoole_WebSocket_Server_unpack,        ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

const zend_function_entry swoole_websocket_frame_methods[] =
{
    PHP_ME(swoole_websocket_frame, __toString, arginfo_class_Swoole_WebSocket_Frame___toString, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,      arginfo_class_Swoole_WebSocket_Frame_pack,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,    arginfo_class_Swoole_WebSocket_Frame_unpack,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void WebSocket::construct_frame(zval *zframe, zend_long opcode, zval *zpayload, uint8_t flags) {
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
    if (flags & WebSocket::FLAG_RSV1) {
        flags |= WebSocket::FLAG_COMPRESS;
    }
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("opcode"), opcode);
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("flags"), flags);
    /* BC */
    zend_update_property_bool(
        swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("finish"), flags & WebSocket::FLAG_FIN);
}

bool FrameObject::uncompress(zval *zpayload, const char *data, size_t length) {
#ifndef SW_HAVE_ZLIB
    swoole_warning("The compressed websocket data frame is received, the `zlib` supports is required");
    return false;
#else
    String zlib_buffer(length + SW_WEBSOCKET_DEFAULT_PAYLOAD_SIZE, sw_zend_string_allocator());
    if (sw_likely(WebSocket::message_uncompress(&zlib_buffer, data, length))) {
        zend::assign_zend_string_by_val(zpayload, zlib_buffer.str, zlib_buffer.length);
        zlib_buffer.release();
        return true;
    } else {
        return false;
    }
#endif
}

bool FrameObject::pack(String *buffer) {
    const char *ptr = nullptr;
    size_t len = 0;

    if (sw_unlikely(opcode > SW_WEBSOCKET_OPCODE_MAX)) {
        php_swoole_fatal_error(E_WARNING, "the maximum value of opcode is %d", SW_WEBSOCKET_OPCODE_MAX);
        return false;
    }

    zend::String str_zdata;
    if (data && !ZVAL_IS_NULL(data)) {
        str_zdata = data;
        ptr = str_zdata.val();
        len = str_zdata.len();
    }

#ifndef SW_HAVE_ZLIB
    swoole_warning("Unable to compress websocket data frame, the `zlib` supports is required");
    return false;
#else
    if ((flags & WebSocket::FLAG_COMPRESS) && len > 0) {
        String *zlib_buffer = sw_tg_buffer();
        zlib_buffer->clear();
        if (WebSocket::message_compress(zlib_buffer, ptr, len, Z_DEFAULT_COMPRESSION)) {
            ptr = zlib_buffer->str;
            len = zlib_buffer->length;
            sw_set_bit(flags, WebSocket::FLAG_RSV1);
        } else {
            sw_unset_bit(flags, WebSocket::FLAG_RSV1);
        }
    }
#endif

    buffer->clear();
    if (UNEXPECTED(opcode == WebSocket::OPCODE_CLOSE)) {
        return WebSocket::pack_close_frame(buffer, code, ptr, len, flags);
    } else {
        return WebSocket::encode(buffer, ptr, len, opcode, flags);
    }
}

FrameObject::FrameObject(zval *zdata, zend_long _opcode, zend_long _flags, zend_long _code) {
    if (Z_TYPE_P(zdata) == IS_OBJECT && instanceof_function(Z_OBJCE_P(zdata), swoole_websocket_frame_ce)) {
        zval *ztmp = nullptr;
        if ((ztmp = sw_zend_read_property_ex(swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_OPCODE), 1))) {
            opcode = zval_get_long(ztmp);
        } else {
            opcode = WebSocket::OPCODE_TEXT;
        }
        if (opcode == WebSocket::OPCODE_CLOSE) {
            if ((ztmp = sw_zend_read_property_not_null_ex(
                     swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_CODE), 1))) {
                code = zval_get_long(ztmp);
            } else {
                code = WebSocket::CLOSE_NORMAL;
            }
            data = sw_zend_read_property_not_null_ex(
                swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_REASON), 1);
        } else {
            data =
                sw_zend_read_property_not_null_ex(swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_DATA), 1);
        }
        if ((ztmp = sw_zend_read_property_ex(swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_FLAGS), 1))) {
            flags = zval_get_long(ztmp) & WebSocket::FLAGS_ALL;
        }
        if ((ztmp = sw_zend_read_property_not_null_ex(
                 swoole_websocket_frame_ce, zdata, SW_ZSTR_KNOWN(SW_ZEND_STR_FINISH), 1))) {
            if (zval_is_true(ztmp)) {
                sw_set_bit(flags, WebSocket::FLAG_FIN);
            } else {
                sw_unset_bit(flags, WebSocket::FLAG_FIN);
            }
        }
    } else {
        opcode = _opcode;
        flags = _flags & WebSocket::FLAGS_ALL;
        code = _code;
        data = zdata;
    }
}

void swoole_websocket_onBeforeHandshakeResponse(Server *serv, int server_fd, HttpContext *ctx) {
    auto cb = php_swoole_server_get_callback(serv, server_fd, SW_SERVER_CB_onBeforeHandshakeResponse);
    if (cb) {
        zval args[3];
        args[0] = *php_swoole_server_zval_ptr(serv);
        args[1] = *ctx->request.zobject;
        args[2] = *ctx->response.zobject;
        if (UNEXPECTED(!zend::function::call(cb, 3, args, nullptr, serv->is_enable_coroutine()))) {
            php_swoole_error(
                E_WARNING, "%s->onBeforeHandshakeResponse handler error", ZSTR_VAL(swoole_websocket_server_ce->name));
            serv->close(ctx->fd, false);
        }
    }
}

void swoole_websocket_onOpen(Server *serv, HttpContext *ctx) {
    Connection *conn = serv->get_connection_by_session_id(ctx->fd);
    if (!conn) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_NOT_EXIST, "session[%ld] is closed", ctx->fd);
        return;
    }
    auto cb = php_swoole_server_get_callback(serv, conn->server_fd, SW_SERVER_CB_onOpen);
    if (cb) {
        zval args[2];
        args[0] = *php_swoole_server_zval_ptr(serv);
        args[1] = *ctx->request.zobject;
        if (UNEXPECTED(!zend::function::call(cb, 2, args, nullptr, serv->is_enable_coroutine()))) {
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

    Server *serv = nullptr;
    Connection *conn = nullptr;

    if (!ctx->co_socket) {
        serv = (Server *) ctx->private_data;
        conn = serv->get_connection_by_session_id(ctx->fd);
        if (!conn) {
            swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_NOT_EXIST, "session[%ld] is closed", ctx->fd);
            return false;
        }
    }

    if (conn) {
        conn->websocket_status = WebSocket::STATUS_ACTIVE;
        ListenPort *port = serv->get_port_by_server_fd(conn->server_fd);
        if (port && !port->websocket_settings.protocol.empty()) {
            ctx->set_header(ZEND_STRL("Sec-WebSocket-Protocol"), port->websocket_settings.protocol, false);
        }
        swoole_websocket_onBeforeHandshakeResponse(serv, conn->server_fd, ctx);
    } else {
        Socket *sock = (Socket *) ctx->private_data;
        sock->open_length_check = 1;
        sock->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        sock->protocol.package_length_offset = 0;
        sock->protocol.package_body_offset = 0;
        sock->protocol.get_package_length = WebSocket::get_package_length;
    }

    ctx->response.status = SW_HTTP_SWITCHING_PROTOCOLS;
    ctx->upgrade = 1;

    ctx->end(nullptr, &retval);
    return Z_TYPE(retval) == IS_TRUE;
}

#ifdef SW_HAVE_ZLIB
bool WebSocket::message_uncompress(String *buffer, const char *in, size_t in_len) {
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
            buffer->length += zstream.total_out;
        }
        if (status == Z_STREAM_END || (status == Z_OK && zstream.avail_in == 0)) {
            ret = true;
            break;
        }
        if (status != Z_OK) {
            break;
        }
        if (buffer->length + (SW_BUFFER_SIZE_STD / 2) >= buffer->size) {
            buffer->extend();
        }
    }
    inflateEnd(&zstream);

    if (!ret) {
        php_swoole_fatal_error(E_WARNING, "inflate() failed, Error: %s[%d]", zError(status), status);
        return false;
    }
    return true;
}

bool WebSocket::message_compress(String *buffer, const char *data, size_t length, int level) {
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
        php_swoole_fatal_error(E_WARNING, "deflateInit2() failed, Error: [%d]", status);
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
        php_swoole_fatal_error(E_WARNING, "Failed to compress outgoing frame");
        return false;
    }

    if (status != Z_OK) {
        php_swoole_fatal_error(E_WARNING, "deflate() failed, Error: [%d]", status);
        return false;
    }

    buffer->length = bytes_written - 4;

    return true;
}
#endif

int swoole_websocket_onMessage(Server *serv, RecvData *req) {
    SessionId fd = req->info.fd;
    uchar flags = 0;
    uchar opcode = 0;
    auto port = serv->get_port_by_session_id(fd);
    if (!port) {
        return SW_ERR;
    }

    zval zdata;
    php_swoole_get_recv_data(serv, &zdata, req);

    WebSocket::parse_ext_flags(req->info.ext_flags, &opcode, &flags);

    if ((opcode == WebSocket::OPCODE_CLOSE && !port->websocket_settings.open_close_frame) ||
        (opcode == WebSocket::OPCODE_PING && !port->websocket_settings.open_ping_frame) ||
        (opcode == WebSocket::OPCODE_PONG && !port->websocket_settings.open_pong_frame)) {
        if (opcode == WebSocket::OPCODE_PING) {
            String frame(SW_WEBSOCKET_FRAME_HEADER_SIZE + req->info.len, sw_php_allocator());
            WebSocket::encode(&frame, req->data, req->info.len, WebSocket::OPCODE_PONG, WebSocket::FLAG_FIN);
            serv->send(fd, frame.str, frame.length);
        }
        zval_ptr_dtor(&zdata);
        return SW_OK;
    }

    // RFC 7692: uncompress websocket data
    // See https://datatracker.ietf.org/doc/html/rfc7692
    if (flags & WebSocket::FLAG_RSV1) {
        zval zpayload;
        auto rs = FrameObject::uncompress(&zpayload, Z_STRVAL(zdata), Z_STRLEN(zdata));
        zval_ptr_dtor(&zdata);
        if (!rs) {
            return SW_OK;
        }
        zdata = zpayload;
    }

    auto cb = php_swoole_server_get_callback(serv, req->info.server_fd, SW_SERVER_CB_onMessage);
    zval args[2];

    args[0] = *php_swoole_server_zval_ptr(serv);
    WebSocket::construct_frame(&args[1], opcode, &zdata, flags);
    zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(&args[1]), ZEND_STRL("fd"), fd);

    if (UNEXPECTED(!zend::function::call(cb, 2, args, nullptr, serv->is_enable_coroutine()))) {
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
                           nullptr,
                           swoole_websocket_server_methods,
                           swoole_http_server);
#ifndef SW_THREAD
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_websocket_server);
#endif
    SW_SET_CLASS_CLONEABLE(swoole_websocket_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_websocket_server, sw_zend_class_unset_property_deny);

    SW_INIT_CLASS_ENTRY(swoole_websocket_frame, "Swoole\\WebSocket\\Frame", nullptr, swoole_websocket_frame_methods);
    zend_class_implements(swoole_websocket_frame_ce, 1, zend_ce_stringable);
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_websocket_frame_ce, ZEND_STRL("data"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("opcode"), WebSocket::OPCODE_TEXT, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_websocket_frame_ce, ZEND_STRL("flags"), WebSocket::FLAG_FIN, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_websocket_frame_ce, ZEND_STRL("finish"), ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY_EX(
        swoole_websocket_closeframe, "Swoole\\WebSocket\\CloseFrame", nullptr, nullptr, swoole_websocket_frame);
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
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_CLOSE_SERVICE_RESTART", WebSocket::CLOSE_SERVICE_RESTART);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_TRY_AGAIN_LATER", WebSocket::CLOSE_TRY_AGAIN_LATER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_BAD_GATEWAY", WebSocket::CLOSE_BAD_GATEWAY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_WEBSOCKET_CLOSE_TLS", WebSocket::CLOSE_TLS);
    /* swoole namespace }}} */

    /* BC */
    // status
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CONNECTION", WebSocket::STATUS_CONNECTION);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE", WebSocket::STATUS_HANDSHAKE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_FRAME", WebSocket::STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_ACTIVE", WebSocket::STATUS_ACTIVE);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CLOSING", WebSocket::STATUS_CLOSING);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE_FAILED", WebSocket::STATUS_HANDSHAKE_FAILED);
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
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_CLOSE_SERVICE_RESTART", WebSocket::CLOSE_SERVICE_RESTART);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_TRY_AGAIN_LATER", WebSocket::CLOSE_TRY_AGAIN_LATER);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_BAD_GATEWAY", WebSocket::CLOSE_BAD_GATEWAY);
    SW_REGISTER_LONG_CONSTANT("WEBSOCKET_CLOSE_TLS", WebSocket::CLOSE_TLS);
}

void php_swoole_server_set_websocket_option(ListenPort *port, zend_array *vht) {
    WebSocket::apply_setting(port->websocket_settings, vht, true);
}

void WebSocket::apply_setting(WebSocketSettings &settings, zend_array *vht, bool in_server) {
    zval *ztmp;
    if (php_swoole_array_get_value(vht, "websocket_subprotocol", ztmp)) {
        settings.protocol = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "websocket_mask", ztmp)) {
        settings.mask = zval_is_true(ztmp);
    } else {
        settings.mask = in_server ? false : true;
    }
#ifdef SW_HAVE_ZLIB
    if (php_swoole_array_get_value(vht, "websocket_compression", ztmp)) {
        settings.compression = zval_is_true(ztmp);
    }
#endif
    if (php_swoole_array_get_value(vht, "open_websocket_close_frame", ztmp)) {
        settings.open_close_frame = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "open_websocket_ping_frame", ztmp)) {
        settings.open_ping_frame = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "open_websocket_pong_frame", ztmp)) {
        settings.open_pong_frame = zval_is_true(ztmp);
    }
    settings.in_server = in_server;
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

static inline void swoole_websocket_server_pack(zval *zdata, zend_long opcode, zend_long flags, zval *return_value) {
    FrameObject frame{zdata, opcode, flags};
    String buffer(SW_WEBSOCKET_FRAME_HEADER_SIZE + frame.get_data_size(), sw_zend_string_allocator());

    if (sw_unlikely(!frame.pack(&buffer))) {
        RETURN_EMPTY_STRING();
    }

    auto packed_str = zend::fetch_zend_string_by_val(buffer.str);
    ZSTR_VAL(packed_str)[buffer.length] = '\0';
    ZSTR_LEN(packed_str) = buffer.length;
    buffer.release();
    RETURN_STR(packed_str);
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

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_LONG(fd)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(code)
    Z_PARAM_STRING(data, length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    String buffer(SW_WEBSOCKET_FRAME_HEADER_SIZE + length + 2, sw_zend_string_allocator());
    if (!WebSocket::pack_close_frame(&buffer, code, data, length, 0)) {
        RETURN_FALSE;
    }
    RETURN_BOOL(swoole_websocket_server_close(serv, fd, &buffer, 1));
}

static PHP_METHOD(swoole_websocket_server, ping) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long fd = 0;
    zend_string *zpayload = zend_empty_string;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(fd)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR(zpayload)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval zdata = {};
    ZVAL_STR(&zdata, zpayload);
    FrameObject frame{&zdata, WebSocket::OPCODE_PING, WebSocket::FLAG_FIN};

    String buffer(SW_WEBSOCKET_FRAME_HEADER_SIZE + frame.get_data_size(), sw_zend_string_allocator());
    if (sw_unlikely(!frame.pack(&buffer))) {
        swoole_set_last_error(SW_ERROR_WEBSOCKET_PACK_FAILED);
        RETURN_FALSE;
    }

    RETURN_BOOL(swoole_websocket_server_push(serv, fd, &buffer));
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

    Connection *conn = serv->get_connection_verify(fd);
    if (sw_unlikely(!conn)) {
        swoole_set_last_error(SW_ERROR_SESSION_NOT_EXIST);
        php_swoole_fatal_error(E_WARNING, "session#" ZEND_LONG_FMT " does not exists", fd);
        RETURN_FALSE;
    }

    FrameObject frame{zdata, opcode, flags};

#ifdef SW_HAVE_ZLIB
    if (conn->websocket_compression) {
        sw_set_bit(frame.flags, WebSocket::FLAG_COMPRESS);
    }
#endif
    // WebSocket server must not set data mask
    sw_unset_bit(frame.flags, WebSocket::FLAG_MASK);

    String buffer(SW_WEBSOCKET_FRAME_HEADER_SIZE + frame.get_data_size(), sw_zend_string_allocator());

    if (sw_unlikely(!frame.pack(&buffer))) {
        swoole_set_last_error(SW_ERROR_WEBSOCKET_PACK_FAILED);
        RETURN_FALSE;
    }

    RETURN_BOOL(swoole_websocket_server_push(serv, fd, &buffer));
}

static PHP_METHOD(swoole_websocket_server, pack) {
    zval *zdata;
    zend_long opcode = WebSocket::OPCODE_TEXT;
    zend_long flags = WebSocket::FLAG_FIN;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(opcode)
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_websocket_server_pack(zdata, opcode, flags, return_value);
}

static PHP_METHOD(swoole_websocket_frame, __toString) {
    swoole_websocket_server_pack(ZEND_THIS, 0, 0, return_value);
}

static PHP_METHOD(swoole_websocket_server, unpack) {
    char *data;
    size_t length;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(data, length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    WebSocket::Frame frame;

    if (length < sizeof(frame.header)) {
        swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
        RETURN_FALSE;
    }

    if (!WebSocket::decode(&frame, data, length)) {
        swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
        RETURN_FALSE;
    }

    zval zpayload{};
    uint8_t flags = frame.get_flags();

    if (frame.compressed()) {
        if (sw_unlikely(!FrameObject::uncompress(&zpayload, frame.payload, frame.payload_length))) {
            swoole_set_last_error(SW_ERROR_PROTOCOL_ERROR);
            RETURN_FALSE;
        }
    } else {
        ZVAL_STRINGL(&zpayload, frame.payload, frame.payload_length);
    }

    WebSocket::construct_frame(return_value, frame.header.OPCODE, &zpayload, flags);
    zval_ptr_dtor(&zpayload);
}

static PHP_METHOD(swoole_websocket_server, isEstablished) {
    Server *serv = php_swoole_server_get_and_check_server(ZEND_THIS);
    if (sw_unlikely(!serv->is_started())) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    zend_long session_id;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(session_id)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Connection *conn = serv->get_connection_verify(session_id);
    // not isEstablished
    if (!conn || conn->closed || conn->websocket_status < WebSocket::STATUS_ACTIVE) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}
