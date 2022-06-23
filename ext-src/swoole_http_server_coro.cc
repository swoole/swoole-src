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

#include <string>
#include <map>

using swoole::microtime;
using swoole::PHPCoroutine;
using swoole::Server;
using swoole::String;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

using HttpRequest = swoole::http::Request;
using HttpResponse = swoole::http::Response;
using HttpContext = swoole::http::Context;

#ifdef SW_USE_HTTP2
namespace http2 = swoole::http2;
using Http2Stream = http2::Stream;
using Http2Session = http2::Session;
#endif

static zend_class_entry *swoole_http_server_coro_ce;
static zend_object_handlers swoole_http_server_coro_handlers;

static bool http_context_send_data(HttpContext *ctx, const char *data, size_t length);
static bool http_context_sendfile(HttpContext *ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
static bool http_context_disconnect(HttpContext *ctx);

#ifdef SW_USE_HTTP2
static void http2_server_onRequest(Http2Session *session, Http2Stream *stream);
#endif

class http_server {
  public:
    Socket *socket;
    zend_fcall_info_cache *default_handler;
    std::map<std::string, zend_fcall_info_cache> handlers;
    zval zcallbacks;
    bool running;
    std::list<Socket *> clients;

    /* options */
    bool http_parse_cookie : 1;
    bool http_parse_post : 1;
    bool http_parse_files : 1;
#ifdef SW_HAVE_COMPRESSION
    bool http_compression : 1;
#endif
#ifdef SW_HAVE_ZLIB
    bool websocket_compression : 1;
#endif
    char *upload_tmp_dir;
#ifdef SW_HAVE_COMPRESSION
    uint8_t http_compression_level;
    uint32_t compression_min_length;
#endif

    http_server(enum swSocketType type) {
        socket = new Socket(type);
        default_handler = nullptr;
        array_init(&zcallbacks);
        running = true;

        http_parse_cookie = true;
        http_parse_post = true;
        http_parse_files = false;
#ifdef SW_HAVE_COMPRESSION
        http_compression = true;
        http_compression_level = SW_Z_BEST_SPEED;
        compression_min_length = SW_COMPRESSION_MIN_LENGTH_DEFAULT;
#endif
#ifdef SW_HAVE_ZLIB
        websocket_compression = false;
#endif
        upload_tmp_dir = sw_strdup("/tmp");
    }

    ~http_server() {
        sw_free(upload_tmp_dir);
    }

    void set_handler(std::string pattern, zval *zcallback, const zend_fcall_info_cache *fci_cache) {
        handlers[pattern] = *fci_cache;
        if (pattern == "/") {
            default_handler = &handlers[pattern];
        }
        Z_ADDREF_P(zcallback);
        add_assoc_zval_ex(&zcallbacks, pattern.c_str(), pattern.length(), zcallback);
    }

    zend_fcall_info_cache *get_handler(HttpContext *ctx) {
        for (auto i = handlers.begin(); i != handlers.end(); i++) {
            if (&i->second == default_handler) {
                continue;
            }
            if (swoole_strcasect(ctx->request.path, ctx->request.path_len, i->first.c_str(), i->first.length())) {
                return &i->second;
            }
        }
        return default_handler;
    }

    HttpContext *create_context(Socket *conn, zval *zconn) {
        HttpContext *ctx = swoole_http_context_new(conn->get_fd());
        ctx->parse_body = http_parse_post;
        ctx->parse_cookie = http_parse_cookie;
        ctx->parse_files = http_parse_files;
#ifdef SW_HAVE_COMPRESSION
        ctx->enable_compression = http_compression;
        ctx->compression_level = http_compression_level;
        ctx->compression_min_length = compression_min_length;
#endif
#ifdef SW_HAVE_ZLIB
        ctx->websocket_compression = websocket_compression;
#endif
        ctx->upload_tmp_dir = upload_tmp_dir;

        ctx->bind(conn);

        swoole_http_parser *parser = &ctx->parser;
        parser->data = ctx;
        swoole_http_parser_init(parser, PHP_HTTP_REQUEST);

        zend_update_property_ex(
            swoole_http_response_ce, SW_Z8_OBJ_P(ctx->response.zobject), SW_ZSTR_KNOWN(SW_ZEND_STR_SOCKET), zconn);

        return ctx;
    }

#ifdef SW_USE_HTTP2
    void recv_http2_frame(HttpContext *ctx) {
        Socket *sock = (Socket *) ctx->private_data;
        http2::send_setting_frame(&sock->protocol, sock->get_socket());

        sock->open_length_check = true;
        sock->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
        sock->protocol.package_length_offset = 0;
        sock->protocol.package_body_offset = 0;
        sock->protocol.get_package_length = http2::get_frame_length;

        Http2Session session(ctx->fd);
        session.default_ctx = ctx;
        session.handle = http2_server_onRequest;
        session.private_data = this;
        session.is_coro = true;

        while (true) {
            auto buffer = sock->get_read_buffer();
            ssize_t retval = sock->recv_packet();
            if (sw_unlikely(retval <= 0)) {
                break;
            }
            swoole_http2_server_parse(&session, buffer->str);
        }

        /* default_ctx does not blong to session object */
        session.default_ctx = nullptr;

        ctx->detached = 1;
        zval_dtor(ctx->request.zobject);
        zval_dtor(ctx->response.zobject);
    }
#endif
};

typedef struct {
    http_server *server;
    zend_object std;
} http_server_coro_t;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http_server_coro, __construct);
static PHP_METHOD(swoole_http_server_coro, set);
static PHP_METHOD(swoole_http_server_coro, handle);
static PHP_METHOD(swoole_http_server_coro, start);
static PHP_METHOD(swoole_http_server_coro, shutdown);
static PHP_METHOD(swoole_http_server_coro, onAccept);
static PHP_METHOD(swoole_http_server_coro, __destruct);
SW_EXTERN_C_END

// clang-format off

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
    ZEND_ARG_INFO(0, reuse_port)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_handle, 0, 0, 2)
    ZEND_ARG_INFO(0, pattern)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_http_server_coro_methods[] =
{
    PHP_ME(swoole_http_server_coro, __construct, arginfo_swoole_http_server_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, set, arginfo_swoole_http_server_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, handle, arginfo_swoole_http_server_coro_handle, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, onAccept, arginfo_swoole_void, ZEND_ACC_PRIVATE)
    PHP_ME(swoole_http_server_coro, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server_coro, shutdown, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

static zend_object *php_swoole_http_server_coro_create_object(zend_class_entry *ce) {
    http_server_coro_t *hsc = (http_server_coro_t *) zend_object_alloc(sizeof(http_server_coro_t), ce);
    zend_object_std_init(&hsc->std, ce);
    object_properties_init(&hsc->std, ce);
    hsc->std.handlers = &swoole_http_server_coro_handlers;
    return &hsc->std;
}

static sw_inline http_server_coro_t *php_swoole_http_server_coro_fetch_object(zend_object *obj) {
    return (http_server_coro_t *) ((char *) obj - swoole_http_server_coro_handlers.offset);
}

static sw_inline http_server *http_server_get_object(zend_object *obj) {
    return php_swoole_http_server_coro_fetch_object(obj)->server;
}

static inline void http_server_set_error(zval *zobject, Socket *sock) {
    zend_update_property_long(swoole_http_server_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), sock->errCode);
    zend_update_property_string(swoole_http_server_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), sock->errMsg);
}

static bool http_context_send_data(HttpContext *ctx, const char *data, size_t length) {
    Socket *sock = (Socket *) ctx->private_data;
    return sock->send_all(data, length) == (ssize_t) length;
}

static bool http_context_sendfile(HttpContext *ctx, const char *file, uint32_t l_file, off_t offset, size_t length) {
    Socket *sock = (Socket *) ctx->private_data;
    return sock->sendfile(file, offset, length);
}

static bool http_context_disconnect(HttpContext *ctx) {
    Socket *sock = (Socket *) ctx->private_data;
    return sock->close();
}

static void php_swoole_http_server_coro_free_object(zend_object *object) {
    http_server_coro_t *hsc = php_swoole_http_server_coro_fetch_object(object);
    if (hsc->server) {
        http_server *hs = hsc->server;
        zval_ptr_dtor(&hs->zcallbacks);
        delete hs;
    }
    zend_object_std_dtor(&hsc->std);
}

void HttpContext::init(Socket *sock) {
    parse_cookie = 1;
    parse_body = 1;
    parse_files = 1;
#ifdef SW_HAVE_COMPRESSION
    enable_compression = 1;
    compression_level = SW_Z_BEST_SPEED;
#endif
#ifdef SW_HAVE_ZLIB
    websocket_compression = 0;
#endif
    upload_tmp_dir = "/tmp";
    bind(sock);
}

void HttpContext::bind(Socket *sock) {
    private_data = sock;
    co_socket = 1;
    send = http_context_send_data;
    sendfile = http_context_sendfile;
    close = http_context_disconnect;
}

void php_swoole_http_server_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_http_server_coro,
                        "Swoole\\Coroutine\\Http\\Server",
                        nullptr,
                        "Co\\Http\\Server",
                        swoole_http_server_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_server_coro);
    SW_SET_CLASS_CLONEABLE(swoole_http_server_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http_server_coro);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_server_coro,
                               php_swoole_http_server_coro_create_object,
                               php_swoole_http_server_coro_free_object,
                               http_server_coro_t,
                               std);
    swoole_http_server_coro_ce->ce_flags |= ZEND_ACC_FINAL;
    swoole_http_server_coro_handlers.get_gc = [](sw_zend7_object *object, zval **gc_data, int *gc_count) {
        http_server_coro_t *hs = php_swoole_http_server_coro_fetch_object(SW_Z7_OBJ_P(object));
        *gc_data = &hs->server->zcallbacks;
        *gc_count = 1;
        return zend_std_get_properties(object);
    };

    zend_declare_property_long(swoole_http_server_coro_ce, ZEND_STRL("fd"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_server_coro_ce, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_server_coro_ce, ZEND_STRL("port"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_server_coro_ce, ZEND_STRL("ssl"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_server_coro_ce, ZEND_STRL("settings"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_server_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_server_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_http_server_coro, __construct) {
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_bool ssl = 0;
    zend_bool reuse_port = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 4)
    Z_PARAM_STRING(host, l_host)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(port)
    Z_PARAM_BOOL(ssl)
    Z_PARAM_BOOL(reuse_port)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_server_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("host"), host, l_host);
    zend_update_property_bool(swoole_http_server_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("ssl"), ssl);

    // check host
    if (l_host == 0) {
        zend_throw_exception_ex(swoole_exception_ce, EINVAL, "host is empty");
        RETURN_FALSE;
    }

    http_server_coro_t *hsc = php_swoole_http_server_coro_fetch_object(Z_OBJ_P(ZEND_THIS));
    std::string host_str(host, l_host);
    hsc->server = new http_server(swoole::network::Socket::convert_to_type(host_str));
    Socket *sock = hsc->server->socket;

    if (reuse_port) {
        sock->get_socket()->set_reuse_port();
    }

    if (!sock->bind(host_str, port)) {
        http_server_set_error(ZEND_THIS, sock);
        zend_throw_exception_ex(swoole_exception_ce, sock->errCode, "bind(%s:%d) failed", host, (int) port);
        RETURN_FALSE;
    }
    // check ssl
    if (ssl) {
#ifndef SW_USE_OPENSSL
        zend_throw_exception_ex(
            swoole_exception_ce,
            EPROTONOSUPPORT,
            "you must configure with `--enable-openssl` to support ssl connection when compiling Swoole");
        RETURN_FALSE;
#else
        /* we have to call ssl_check_context after user setProtocols */
        zval *zsettings =
            sw_zend_read_and_convert_property_array(swoole_http_server_coro_ce, ZEND_THIS, ZEND_STRL("settings"), 0);
        add_assoc_bool(zsettings, "open_ssl", 1);
        sock->enable_ssl_encrypt();
#endif
    }
    if (!sock->listen()) {
        http_server_set_error(ZEND_THIS, sock);
        zend_throw_exception_ex(swoole_exception_ce, sock->errCode, "listen() failed");
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_http_server_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("fd"), sock->get_fd());
    zend_update_property_long(
        swoole_http_server_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("port"), sock->get_bind_port());
}

static PHP_METHOD(swoole_http_server_coro, handle) {
    char *pattern;
    size_t pattern_len;

    http_server *hs = http_server_get_object(Z_OBJ_P(ZEND_THIS));
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(pattern, pattern_len)
    Z_PARAM_FUNC(fci, fci_cache)
    ZEND_PARSE_PARAMETERS_END();

    std::string key(pattern, pattern_len);
    hs->set_handler(key, ZEND_CALL_ARG(execute_data, 2), &fci_cache);
}

static PHP_METHOD(swoole_http_server_coro, set) {
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(zset) == 0) {
        RETURN_FALSE;
    } else {
        zval *zsettings =
            sw_zend_read_and_convert_property_array(swoole_http_server_coro_ce, ZEND_THIS, ZEND_STRL("settings"), 0);
        php_array_merge(Z_ARRVAL_P(zsettings), Z_ARRVAL_P(zset));
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_http_server_coro, start) {
    http_server *hs = http_server_get_object(Z_OBJ_P(ZEND_THIS));
    Socket *sock = hs->socket;

    /* get callback fci cache */
    char *func_name = nullptr;
    zend_fcall_info_cache fci_cache;
    zval zcallback;
    ZVAL_STRING(&zcallback, "onAccept");
    if (!sw_zend_is_callable_at_frame(
            &zcallback, ZEND_THIS, execute_data, 0, &func_name, nullptr, &fci_cache, nullptr)) {
        php_swoole_fatal_error(E_CORE_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    /* check settings */
    zval *zsettings =
        sw_zend_read_and_convert_property_array(swoole_http_server_coro_ce, ZEND_THIS, ZEND_STRL("settings"), 0);
    php_swoole_socket_set_protocol(hs->socket, zsettings);
    HashTable *vht = Z_ARRVAL_P(zsettings);
    zval *ztmp;
    // parse cookie header
    if (php_swoole_array_get_value(vht, "http_parse_cookie", ztmp)) {
        hs->http_parse_cookie = zval_is_true(ztmp);
    }
    // parse x-www-form-urlencoded form data
    if (php_swoole_array_get_value(vht, "http_parse_post", ztmp)) {
        hs->http_parse_post = zval_is_true(ztmp);
    }
    // parse multipart/form-data file uploads
    if (php_swoole_array_get_value(vht, "http_parse_files", ztmp)) {
        hs->http_parse_files = zval_is_true(ztmp);
    }
#ifdef SW_HAVE_COMPRESSION
    // http content compression
    if (php_swoole_array_get_value(vht, "http_compression", ztmp)) {
        hs->http_compression = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "http_compression_level", ztmp) ||
        php_swoole_array_get_value(vht, "http_gzip_level", ztmp)) {
        zend_long level = zval_get_long(ztmp);
        if (level > UINT8_MAX) {
            level = UINT8_MAX;
        } else if (level < 0) {
            level = 0;
        }
        hs->http_compression_level = level;
    }
    if (php_swoole_array_get_value(vht, "compression_min_length", ztmp)) {
        hs->compression_min_length = zval_get_long(ztmp);
    }
#endif
#ifdef SW_HAVE_ZLIB
    if (php_swoole_array_get_value(vht, "websocket_compression", ztmp)) {
        hs->websocket_compression = zval_is_true(ztmp);
    }
#endif
    // temporary directory for HTTP uploaded file.
    if (php_swoole_array_get_value(vht, "upload_tmp_dir", ztmp)) {
        zend::String str_v(ztmp);
        if (php_swoole_create_dir(str_v.val(), str_v.len()) < 0) {
            php_swoole_fatal_error(E_ERROR, "Unable to create upload_tmp_dir[%s]", str_v.val());
            return;
        }
        if (hs->upload_tmp_dir) {
            sw_free(hs->upload_tmp_dir);
        }
        hs->upload_tmp_dir = str_v.dup();
    }

    php_swoole_http_server_init_global_variant();

    while (hs->running) {
        auto conn = sock->accept();
        if (conn) {
            zval zsocket;
            php_swoole_init_socket_object(&zsocket, conn);
            long cid = PHPCoroutine::create(&fci_cache, 1, &zsocket);
            zval_dtor(&zsocket);
            if (cid < 0) {
                goto _wait_1s;
            }
        } else {
            /*
             * Too many connection, wait 1s
             */
            if (sock->errCode == EMFILE || sock->errCode == ENFILE) {
            _wait_1s:
                System::sleep(SW_ACCEPT_RETRY_TIME);
            } else if (sock->errCode == ETIMEDOUT || sock->errCode == SW_ERROR_SSL_BAD_CLIENT) {
                continue;
            } else if (sock->errCode == ECANCELED) {
                http_server_set_error(ZEND_THIS, sock);
                break;
            } else {
                http_server_set_error(ZEND_THIS, sock);
                php_swoole_fatal_error(E_WARNING, "accept failed, Error: %s[%d]", sock->errMsg, sock->errCode);
                break;
            }
        }
    }

    zval_dtor(&zcallback);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_server_coro, __destruct) {}

static PHP_METHOD(swoole_http_server_coro, onAccept) {
    http_server *hs = http_server_get_object(Z_OBJ_P(ZEND_THIS));
    zval *zconn;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_OBJECT(zconn)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *sock = php_swoole_get_socket(zconn);
    sock->set_buffer_allocator(sw_zend_string_allocator());
    String *buffer = sock->get_read_buffer();
    HttpContext *ctx = nullptr;
    bool header_completed = false;
    off_t header_crlf_offset = 0;
    size_t total_length;

    hs->clients.push_front(sock);
    auto client_iterator = hs->clients.begin();

#ifdef SW_USE_OPENSSL
    if (sock->ssl_is_enable() && !sock->ssl_handshake()) {
        goto _handshake_failed;
    }
#endif

    while (true) {
    _recv_request : {
        ssize_t retval = sock->recv(buffer->str + buffer->length, buffer->size - buffer->length);
        if (sw_unlikely(retval <= 0)) {
            break;
        }
        buffer->length += retval;
    }

    _parse_request:
        if (!ctx) {
            ctx = hs->create_context(sock, zconn);
        }

        if (!header_completed) {
            ssize_t pos = swoole_strnpos(
                buffer->str + header_crlf_offset, buffer->length - header_crlf_offset, ZEND_STRL("\r\n\r\n"));
            if (pos < 0) {
                if (buffer->length == buffer->size) {
                    ctx->response.status = SW_HTTP_REQUEST_ENTITY_TOO_LARGE;
                    break;
                }
                header_crlf_offset = buffer->length > 4 ? buffer->length - 4 : 0;
                continue;
            }

            size_t header_length = header_crlf_offset + pos;
            header_completed = true;
            header_crlf_offset = 0;

            // The HTTP header must be parsed first
            // Header contains CRLFx2
            header_length += 4;
            size_t parsed_n = ctx->parse(buffer->str, header_length);
            if (parsed_n != header_length) {
                ctx->response.status = SW_HTTP_BAD_REQUEST;
                break;
            }
            buffer->offset += header_length;
            total_length = header_length + ctx->get_content_length();
            if (ctx->get_content_length() > 0 && total_length > sock->protocol.package_max_length) {
                ctx->response.status = SW_HTTP_REQUEST_ENTITY_TOO_LARGE;
                break;
            }
            if (total_length > buffer->size && !buffer->extend(total_length)) {
                ctx->response.status = SW_HTTP_SERVICE_UNAVAILABLE;
                break;
            }
        }

        if (!ctx->completed) {
            // Make sure the complete request package is received
            if (ctx->recv_chunked &&
                memcmp(buffer->str + buffer->length - (sizeof(SW_HTTP_CHUNK_EOF) - 1), SW_STRL(SW_HTTP_CHUNK_EOF)) != 0) {
                goto _recv_request;
            }
            if (buffer->length < total_length) {
                goto _recv_request;
            }

            size_t parsed_n = ctx->parse(buffer->str + buffer->offset, buffer->length - buffer->offset);
            buffer->offset += parsed_n;

            swoole_trace_log(SW_TRACE_CO_HTTP_SERVER,
                             "parsed_n=%zu, length=%zu, offset=%jd, completed=%u",
                             parsed_n,
                             buffer->length,
                             (intmax_t) buffer->offset,
                             ctx->completed);

            if (ctx->parser.state == s_dead) {
                ctx->response.status = SW_HTTP_BAD_REQUEST;
                break;
            }
        }

#ifdef SW_USE_HTTP2
        if (ctx->parser.method == PHP_HTTP_NOT_IMPLEMENTED && buffer->length >= (sizeof(SW_HTTP2_PRI_STRING) - 1) &&
            memcmp(buffer->str, SW_HTTP2_PRI_STRING, sizeof(SW_HTTP2_PRI_STRING) - 1) == 0) {
            buffer->offset = (sizeof(SW_HTTP2_PRI_STRING) - 1);
            hs->recv_http2_frame(ctx);
            /* ownership of ctx has been transferred */
            ctx = nullptr;
            break;
        }
#endif

        zend::assign_zend_string_by_val(&ctx->request.zdata, buffer->pop(SW_BUFFER_SIZE_BIG), total_length);

        zval *zserver = ctx->request.zserver;
        add_assoc_long(zserver, "server_port", hs->socket->get_bind_port());
        add_assoc_long(zserver, "remote_port", (zend_long) sock->get_port());
        add_assoc_string(zserver, "remote_addr", (char *) sock->get_ip());

        zend_fcall_info_cache *fci_cache = hs->get_handler(ctx);
        zval args[2] = {*ctx->request.zobject, *ctx->response.zobject};
        bool keep_alive = swoole_http_should_keep_alive(&ctx->parser) && !ctx->websocket;

        if (fci_cache) {
            if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, 0))) {
                php_swoole_error(E_WARNING, "handler error");
            }
        } else {
            ctx->response.status = SW_HTTP_NOT_FOUND;
        }

        zval_dtor(&args[0]);
        zval_dtor(&args[1]);
        ctx = nullptr;

        if (!hs->running || !keep_alive || php_swoole_socket_is_closed(zconn)) {
            break;
        } else {
            header_completed = false;
            if (buffer->length > 0) {
                goto _parse_request;
            } else {
                goto _recv_request;
            }
        }
    }

    if (ctx) {
        zval_dtor(ctx->request.zobject);
        zval_dtor(ctx->response.zobject);
    }

#ifdef SW_USE_OPENSSL
_handshake_failed:
#endif
    /* notice: do not erase the element when server is shutting down */
    if (hs->running) {
        hs->clients.erase(client_iterator);
    }
}

static PHP_METHOD(swoole_http_server_coro, shutdown) {
    http_server *hs = http_server_get_object(Z_OBJ_P(ZEND_THIS));
    hs->running = false;
    hs->socket->cancel(SW_EVENT_READ);
    /* accept has been canceled, we only need to traverse once */
    for (auto client : hs->clients) {
        client->close();
    }
    hs->clients.clear();
}

#ifdef SW_USE_HTTP2
static void http2_server_onRequest(Http2Session *session, Http2Stream *stream) {
    HttpContext *ctx = stream->ctx;
    http_server *hs = (http_server *) session->private_data;
    Socket *sock = (Socket *) ctx->private_data;
    zval *zserver = ctx->request.zserver;

    add_assoc_long(zserver, "request_time", time(nullptr));
    add_assoc_double(zserver, "request_time_float", microtime());
    add_assoc_long(zserver, "server_port", hs->socket->get_bind_port());
    add_assoc_long(zserver, "remote_port", sock->get_port());
    add_assoc_string(zserver, "remote_addr", (char *) sock->get_ip());
    add_assoc_string(zserver, "server_protocol", (char *) "HTTP/2");

    zend_fcall_info_cache *fci_cache = hs->get_handler(ctx);
    zval args[2] = {*ctx->request.zobject, *ctx->response.zobject};

    if (fci_cache) {
        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, true))) {
            stream->reset(SW_HTTP2_ERROR_INTERNAL_ERROR);
            php_swoole_error(E_WARNING, "%s->onRequest[v2] handler error", ZSTR_VAL(swoole_http_server_ce->name));
        }
    } else {
        ctx->response.status = SW_HTTP_NOT_FOUND;
    }

    zval_ptr_dtor(&args[0]);
    zval_ptr_dtor(&args[1]);
}
#endif
