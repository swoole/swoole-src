/**
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

#include "swoole_http.h"
#include "swoole_server.h"

#include "swoole_llhttp.h"
#include "thirdparty/multipart_parser.h"

namespace swoole {
namespace http_server {

static int http_request_on_url(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_body(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length);
static int http_request_on_headers_complete(llhttp_t *parser);
static int http_request_message_complete(llhttp_t *parser);

static int multipart_body_on_header_field(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_header_value(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_data(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_header_complete(multipart_parser *p);
static int multipart_body_on_data_end(multipart_parser *p);

// clang-format off
static const llhttp_settings_t http_parser_settings =
{
    nullptr,                                // on_message_begin
    nullptr,                                // on_protocol
    http_request_on_url,                    // on_url
    nullptr,                                // on_status
    nullptr,                                // on_method
    nullptr,                                // on_version
    http_request_on_header_field,           // on_header_field
    http_request_on_header_value,           // on_header_value
    nullptr,                                // on_chunk_extension_name
    nullptr,                                // on_chunk_extension_value
    http_request_on_headers_complete,       // on_headers_complete
    http_request_on_body,                   // on_body
    http_request_message_complete,          // on_message_complete
    nullptr,                                // on_protocol_complete
    nullptr,                                // on_url_complete
    nullptr,                                // on_status_complete
    nullptr,                                // on_method_complete
    nullptr,                                // on_version_complete
    nullptr,                                // on_header_field_complete
    nullptr,                                // on_header_value_complete
    nullptr,                                // on_chunk_extension_name_complete
    nullptr,                                // on_chunk_extension_value_complete
    nullptr,                                // on_chunk_header
    nullptr,                                // on_chunk_complete
    nullptr,                                // on_reset
};

static  constexpr multipart_parser_settings mt_parser_settings = {
    multipart_body_on_header_field,
    multipart_body_on_header_value,
    multipart_body_on_data,
    nullptr,
    multipart_body_on_header_complete,
    multipart_body_on_data_end,
    nullptr,
};
// clang-format on

struct ContextImpl {
    llhttp_t parser;
    multipart_parser *mt_parser;

    std::string current_header_name;
    std::string current_input_name;
    std::string current_form_data_name;
    String *form_data_buffer;

    bool completed = false;
    bool is_beginning = true;

    bool parse(Context &ctx, const char *at, size_t length) {
        swoole_llhttp_parser_init(&parser, HTTP_REQUEST, static_cast<void *>(&ctx));
        swoole_llhttp_parser_execute(&parser, &http_parser_settings, at, length);
        return parser.error == HPE_OK && completed;
    }
};

static int http_request_on_url(llhttp_t *parser, const char *at, size_t length) {
    const char *query_start = (const char *) memchr(at, '?', length);
    size_t path_len = query_start ? (size_t) (query_start - at) : length;

    auto *ctx = static_cast<Context *>(parser->data);
    ctx->request_path = std::string(at, path_len);

    if (!query_start || (length - path_len) <= 1) {
        return 0;
    }

    const char *query_str = query_start + 1;
    size_t query_len = length - path_len - 1;
    ctx->query_string = std::string(query_str, query_len);
    return 0;
}

static int http_request_on_header_field(llhttp_t *parser, const char *at, size_t length) {
    auto *ctx = static_cast<Context *>(parser->data);
    ctx->impl->current_header_name = std::string(at, length);
    return 0;
}

static int http_request_on_header_value(llhttp_t *parser, const char *at, size_t length) {
    auto *ctx = static_cast<Context *>(parser->data);
    ContextImpl *impl = ctx->impl;
    ctx->headers[impl->current_header_name] = std::string(at, length);

    if ((parser->method == HTTP_POST || parser->method == HTTP_PUT || parser->method == HTTP_DELETE ||
         parser->method == HTTP_PATCH) &&
        SW_STRCASEEQ(impl->current_header_name.c_str(), impl->current_header_name.length(), "content-type")) {
        if (SW_STR_ISTARTS_WITH(at, length, "application/x-www-form-urlencoded")) {
            ctx->post_form_urlencoded = true;
        } else if (SW_STR_ISTARTS_WITH(at, length, "multipart/form-data")) {
            size_t offset = sizeof("multipart/form-data") - 1;
            char *boundary_str;
            int boundary_len;
            if (!parse_multipart_boundary(at, length, offset, &boundary_str, &boundary_len)) {
                return -1;
            }
            impl->mt_parser = multipart_parser_init(boundary_str, boundary_len, &mt_parser_settings);
            impl->form_data_buffer = new String(SW_BUFFER_SIZE_STD);
            impl->mt_parser->data = ctx;
            swoole_trace_log(SW_TRACE_HTTP, "form_data, boundary_str=%s", boundary_str);
        }
    }
    return 0;
}

static int http_request_on_headers_complete(llhttp_t *parser) {
    auto *ctx = static_cast<Context *>(parser->data);
    ctx->version = parser->http_major * 100 + parser->http_minor;
    ctx->server_protocol = std::string(ctx->version == 101 ? "HTTP/1.1" : "HTTP/1.0");
    ctx->keepalive = llhttp_should_keep_alive(parser);
    return 0;
}

static int http_request_on_body(llhttp_t *parser, const char *at, size_t length) {
    if (length == 0) {
        return 0;
    }

    auto *ctx = static_cast<Context *>(parser->data);
    auto *impl = ctx->impl;

    if (impl->mt_parser != nullptr) {
        multipart_parser *multipart_parser = impl->mt_parser;
        if (impl->is_beginning) {
            /* Compatibility: some clients may send extra EOL */
            do {
                if (*at != '\r' && *at != '\n') {
                    break;
                }
                at++;
                length--;
            } while (length != 0);
            impl->is_beginning = false;
        }
        size_t n = multipart_parser_execute(multipart_parser, at, length);
        if (sw_unlikely(n != length)) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SERVER_INVALID_REQUEST,
                             "parse multipart body failed, %zu/%zu bytes processed",
                             n,
                             length);
        }
    } else {
        ctx->body.append(at, length);
    }

    return impl->completed ? HPE_PAUSED : 0;
}

static int multipart_body_on_header_field(multipart_parser *p, const char *at, size_t length) {
    auto *ctx = static_cast<Context *>(p->data);
    ContextImpl *impl = ctx->impl;
    return http_request_on_header_field(&impl->parser, at, length);
}

static int multipart_body_on_header_value(multipart_parser *p, const char *at, size_t length) {
    auto *ctx = static_cast<Context *>(p->data);
    ContextImpl *impl = ctx->impl;
    const char *header_name = impl->current_header_name.c_str();
    size_t header_len = impl->current_header_name.length();

    if (SW_STRCASEEQ(header_name, header_len, "content-disposition")) {
        std::unordered_map<std::string, std::string> info;
        ParseCookieCallback cb = [&info](char *key, size_t key_len, char *value, size_t value_len) {
            info[std::string(key, key_len)] = std::string(value, value_len);
            return true;
        };
        parse_cookie(at, length, cb);
        auto name = info.find("name");
        auto filename = info.find("filename");
        if (filename == info.end()) {
            impl->current_form_data_name = name->second;
        } else {
            impl->current_input_name = filename->second;
        }
    } else if (SW_STRCASEEQ(header_name, header_len, SW_HTTP_UPLOAD_FILE)) {
        /**
         * When the "SW_HTTP_UPLOAD_FILE" header appears in the request, it indicates that the uploaded file has been
         * saved in a temporary file. The binary content in the message body will be replaced with the temporary
         * filename. However, the Content-Length still reflects the original message size, causing llhttp to believe
         * there is still data to be received. As a result, llhttp fails to trigger the message callback. Therefore, we
         * need to set `ctx->completed = 1` to indicate that the message processing is complete.
         */
        impl->completed = true;
        ctx->files[impl->current_form_data_name] = std::string(at, length);
    }

    return 0;
}

static int multipart_body_on_data(multipart_parser *p, const char *at, size_t length) {
    auto *ctx = static_cast<Context *>(p->data);
    const auto *impl = ctx->impl;
    if (!impl->current_form_data_name.empty()) {
        impl->form_data_buffer->append(at, length);
        return 0;
    }
    if (p->fp == nullptr) {
        return 0;
    }
    ssize_t n = fwrite(at, sizeof(char), length, p->fp);
    if (n != (off_t) length) {
        ctx->files[impl->current_form_data_name] = "ERROR(1)";
        fclose(p->fp);
        p->fp = nullptr;
        swoole_sys_warning("write upload file failed");
    }
    return 0;
}

static int multipart_body_on_header_complete(multipart_parser *p) {
    auto *ctx = static_cast<Context *>(p->data);
    const auto *impl = ctx->impl;
    if (impl->current_input_name.empty()) {
        return 0;
    }

    if (ctx->files.find(impl->current_form_data_name) != ctx->files.end()) {
        return 0;
    }

    char file_path[SW_HTTP_UPLOAD_TMPDIR_SIZE] = "/tmp/swoole.upfile.XXXXXX";
    int tmpfile = swoole_tmpfile(file_path);
    if (tmpfile < 0) {
        return 0;
    }

    FILE *fp = fdopen(tmpfile, "wb+");
    if (fp == nullptr) {
        swoole_sys_warning("fopen(%s) failed", file_path);
        return 0;
    }
    p->fp = fp;
    ctx->files[impl->current_form_data_name] = file_path;

    return 0;
}

static int multipart_body_on_data_end(multipart_parser *p) {
    auto *ctx = static_cast<Context *>(p->data);
    ContextImpl *impl = ctx->impl;

    if (!impl->current_form_data_name.empty()) {
        ctx->form_data[impl->current_form_data_name] = impl->form_data_buffer->to_std_string();
        impl->form_data_buffer->clear();
    }

    if (p->fp != nullptr) {
        fclose(p->fp);
        p->fp = nullptr;
    }

    impl->current_header_name.clear();
    impl->current_input_name.clear();
    impl->current_form_data_name.clear();

    return 0;
}

static int http_request_message_complete(llhttp_t *p) {
    const auto *ctx = static_cast<Context *>(p->data);
    auto *impl = ctx->impl;

    if (impl->form_data_buffer) {
        delete impl->form_data_buffer;
        impl->form_data_buffer = nullptr;
    }

    impl->completed = true;
    return HPE_PAUSED;
}

bool Context::end(const char *data, size_t length) {
    char buf[1024];
    sw_tg_buffer()->clear();
    sw_tg_buffer()->append(SW_STRL("HTTP/1.1 "));
    sw_tg_buffer()->append(get_status_message(response.code));
    sw_tg_buffer()->append(SW_STRL("\r\n"));
    if (length > 0) {
        response.headers["Content-Length"] = std::to_string(length);
    }
    for (auto &iter : response.headers) {
        size_t n = sw_snprintf(buf, sizeof(buf), "%s: %s\r\n", iter.first.c_str(), iter.second.c_str());
        sw_tg_buffer()->append(buf, n);
    }
    sw_tg_buffer()->append(SW_STRL("\r\n"));
    if (!server_->send(session_id_, sw_tg_buffer()->str, sw_tg_buffer()->length)) {
        swoole_warning("failed to send HTTP header");
        return false;
    }
    if (length > 0 && !server_->send(session_id_, data, length)) {
        swoole_warning("failed to send HTTP body");
        return false;
    }
    if (!keepalive) {
        server_->close(session_id_, false);
    }
    return true;
}

Context::~Context() {
    for (auto &kv : files) {
        if (file_exists(kv.second)) {
            unlink(kv.second.c_str());
        }
    }
}

static std::function<void(Context &ctx)> http_server_on_request;

std::shared_ptr<Server> listen(const std::string &addr, const std::function<void(Context &ctx)> &cb, int mode) {
    auto server = std::make_shared<Server>(static_cast<Server::Mode>(mode));
    auto index = addr.find(':');
    if (index == std::string::npos) {
        swoole_warning("incorrect server listening address");
        return nullptr;
    }

    std::string host = addr.substr(0, index);
    if (host.empty()) {
        host = "0.0.0.0";
    }

    int port = atoi(addr.substr(index + 1).c_str());
    auto port_object = server->add_port(SW_SOCK_TCP, host.c_str(), port);
    if (!port_object) {
        return nullptr;
    }

    http_server_on_request = cb;

    server->onReceive = [](Server *server, RecvData *req) {
        SessionId session_id = req->info.fd;
        Connection *conn = server->get_connection_verify_no_ssl(session_id);
        if (!conn) {
            swoole_error_log(SW_LOG_TRACE, SW_ERROR_SESSION_NOT_EXIST, "session[%ld] is closed", session_id);
            return SW_OK;
        }
        ContextImpl impl;
        Context ctx(server, session_id, &impl);
        if (impl.parse(ctx, req->data, req->info.len)) {
            http_server_on_request(ctx);
        } else {
            server->send(req->session_id(), SW_STRL(SW_HTTP_BAD_REQUEST_PACKET));
        }
        return SW_OK;
    };

    port_object->open_http_protocol = true;

    if (server->create() == SW_ERR) {
        return nullptr;
    }

    return server;
}
}  // namespace http_server
}  // namespace swoole
