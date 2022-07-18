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
#include "swoole_process_pool.h"

using namespace swoole;
using swoole::coroutine::Socket;

using HttpRequest = swoole::http::Request;
using HttpResponse = swoole::http::Response;
using HttpContext = swoole::http::Context;

namespace WebSocket = swoole::websocket;

zend_class_entry *swoole_http_server_ce;
zend_object_handlers swoole_http_server_handlers;

static std::queue<HttpContext *> queued_http_contexts;

static bool http_context_send_data(HttpContext *ctx, const char *data, size_t length);
static bool http_context_sendfile(HttpContext *ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
static bool http_context_disconnect(HttpContext *ctx);

static void http_server_process_request(Server *serv, zend_fcall_info_cache *fci_cache, HttpContext *ctx) {
    zval args[2];
    args[0] = *ctx->request.zobject;
    args[1] = *ctx->response.zobject;
    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s->onRequest handler error", ZSTR_VAL(swoole_http_server_ce->name));
#ifdef SW_HTTP_SERVICE_UNAVAILABLE_PACKET
        ctx->send(ctx, SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET));
#endif
        ctx->close(ctx);
    }
}

int php_swoole_http_server_onReceive(Server *serv, RecvData *req) {
    SessionId session_id = req->info.fd;
    int server_fd = req->info.server_fd;

    Connection *conn = serv->get_connection_verify_no_ssl(session_id);
    if (!conn) {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "session[%ld] is closed", session_id);
        return SW_ERR;
    }

    ListenPort *port = serv->get_port_by_server_fd(server_fd);
    // other server port
    if (!(port->open_http_protocol && php_swoole_server_isset_callback(serv, port, SW_SERVER_CB_onRequest)) &&
        !(port->open_websocket_protocol && php_swoole_server_isset_callback(serv, port, SW_SERVER_CB_onMessage))) {
        return php_swoole_server_onReceive(serv, req);
    }
    // websocket client
    if (conn->websocket_status == WebSocket::STATUS_ACTIVE) {
        return swoole_websocket_onMessage(serv, req);
    }

    if (conn->http2_stream) {
        return swoole_http2_server_onReceive(serv, conn, req);
    }

    HttpContext *ctx = swoole_http_context_new(session_id);
    ctx->init(serv);

    zval *zdata = &ctx->request.zdata;
    php_swoole_get_recv_data(serv, zdata, req);

    swoole_trace_log(SW_TRACE_SERVER,
                     "http request from %ld with %d bytes: <<EOF\n%.*s\nEOF",
                     session_id,
                     (int) Z_STRLEN_P(zdata),
                     (int) Z_STRLEN_P(zdata),
                     Z_STRVAL_P(zdata));

    zval *zrequest_object = ctx->request.zobject;
    zval *zresponse_object = ctx->response.zobject;

    swoole_http_parser *parser = &ctx->parser;
    parser->data = ctx;
    swoole_http_parser_init(parser, PHP_HTTP_REQUEST);

    size_t parsed_n = ctx->parse(Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    if (ctx->parser.state == s_dead) {
        ctx->send(ctx, SW_STRL(SW_HTTP_BAD_REQUEST_PACKET));
        ctx->close(ctx);
        swoole_notice("request is illegal and it has been discarded, %ld bytes unprocessed",
                      Z_STRLEN_P(zdata) - parsed_n);
        goto _dtor_and_return;
    }

    do {
        zval *zserver = ctx->request.zserver;
        Connection *serv_sock = serv->get_connection(conn->server_fd);
        if (serv_sock) {
            add_assoc_long(zserver, "server_port", serv_sock->info.get_port());
        }
        add_assoc_long(zserver, "remote_port", conn->info.get_port());
        add_assoc_string(zserver, "remote_addr", (char *) conn->info.get_ip());
        add_assoc_long(zserver, "master_time", (int) conn->last_recv_time);
    } while (0);

    if (swoole_isset_hook((enum swGlobalHookType) PHP_SWOOLE_HOOK_BEFORE_REQUEST)) {
        swoole_call_hook((enum swGlobalHookType) PHP_SWOOLE_HOOK_BEFORE_REQUEST, ctx);
    }

    // begin to check and call registerd callback
    do {
        zend_fcall_info_cache *fci_cache = nullptr;

        if (conn->websocket_status == WebSocket::STATUS_CONNECTION) {
            fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onHandShake);
            if (fci_cache == nullptr) {
                swoole_websocket_onHandshake(serv, port, ctx);
                goto _dtor_and_return;
            } else {
                conn->websocket_status = WebSocket::STATUS_HANDSHAKE;
                ctx->upgrade = 1;
            }
        } else {
            fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onRequest);
            if (fci_cache == nullptr) {
                swoole_websocket_onRequest(ctx);
                goto _dtor_and_return;
            }
        }
        ctx->private_data_2 = fci_cache;
        if (ctx->onBeforeRequest && !ctx->onBeforeRequest(ctx)) {
            return SW_OK;
        }
        http_server_process_request(serv, fci_cache, ctx);
    } while (0);

_dtor_and_return:
    zval_ptr_dtor(zrequest_object);
    zval_ptr_dtor(zresponse_object);

    return SW_OK;
}

void php_swoole_http_server_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_EX(swoole_http_server, "Swoole\\Http\\Server", nullptr, nullptr, swoole_server);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_server);
    SW_SET_CLASS_CLONEABLE(swoole_http_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server, sw_zend_class_unset_property_deny);
}

void php_swoole_http_server_rinit() {
    // for is_uploaded_file and move_uploaded_file
    if (!SG(rfc1867_uploaded_files)) {
        ALLOC_HASHTABLE(SG(rfc1867_uploaded_files));
        zend_hash_init(SG(rfc1867_uploaded_files), 8, nullptr, nullptr, 0);
    }
}

HttpContext *swoole_http_context_new(SessionId fd) {
    HttpContext *ctx = new HttpContext();

    zval *zrequest_object = &ctx->request._zobject;
    ctx->request.zobject = zrequest_object;
    object_init_ex(zrequest_object, swoole_http_request_ce);
    php_swoole_http_request_set_context(zrequest_object, ctx);

    zval *zresponse_object = &ctx->response._zobject;
    ctx->response.zobject = zresponse_object;
    object_init_ex(zresponse_object, swoole_http_response_ce);
    php_swoole_http_response_set_context(zresponse_object, ctx);

    zend_update_property_long(swoole_http_request_ce, SW_Z8_OBJ_P(zrequest_object), ZEND_STRL("fd"), fd);
    zend_update_property_long(swoole_http_response_ce, SW_Z8_OBJ_P(zresponse_object), ZEND_STRL("fd"), fd);

    swoole_http_init_and_read_property(
        swoole_http_request_ce, zrequest_object, &ctx->request.zserver, ZEND_STRL("server"));
    swoole_http_init_and_read_property(
        swoole_http_request_ce, zrequest_object, &ctx->request.zheader, ZEND_STRL("header"));
    ctx->fd = fd;

    return ctx;
}

void HttpContext::init(Server *serv) {
    parse_cookie = serv->http_parse_cookie;
    parse_body = serv->http_parse_post;
    parse_files = serv->http_parse_files;
#ifdef SW_HAVE_COMPRESSION
    enable_compression = serv->http_compression;
    compression_level = serv->http_compression_level;
    compression_min_length = serv->compression_min_length;
    compression_types = serv->http_compression_types;
#endif
    upload_tmp_dir = serv->upload_tmp_dir;
    bind(serv);
}

void HttpContext::bind(Server *serv) {
    private_data = serv;
    send = http_context_send_data;
    sendfile = http_context_sendfile;
    close = http_context_disconnect;
    onBeforeRequest = swoole_http_server_onBeforeRequest;
    onAfterResponse = swoole_http_server_onAfterResponse;
}

void HttpContext::copy(HttpContext *ctx) {
    parse_cookie = ctx->parse_cookie;
    parse_body = ctx->parse_body;
    parse_files = ctx->parse_files;
#ifdef SW_HAVE_COMPRESSION
    enable_compression = ctx->enable_compression;
    compression_level = ctx->compression_level;
    compression_min_length = ctx->compression_min_length;
    compression_types = ctx->compression_types;
#endif
    co_socket = ctx->co_socket;
    private_data = ctx->private_data;
    upload_tmp_dir = ctx->upload_tmp_dir;
    send = ctx->send;
    sendfile = ctx->sendfile;
    close = ctx->close;
    onBeforeRequest = ctx->onBeforeRequest;
    onAfterResponse = ctx->onAfterResponse;
}

bool HttpContext::is_available() {
    if (!response.zobject) {
        return false;
    }
    if (co_socket) {
        zval rv;
        zval *zconn = zend_read_property_ex(
            swoole_http_response_ce, SW_Z8_OBJ_P(response.zobject), SW_ZSTR_KNOWN(SW_ZEND_STR_SOCKET), 1, &rv);
        if (!zconn || ZVAL_IS_NULL(zconn)) {
            return false;
        }
        if (php_swoole_socket_is_closed(zconn)) {
            return false;
        }
    } else {
        Server *serv = (Server *) private_data;
        Connection *conn = serv->get_connection_by_session_id(fd);
        if (!conn || conn->closed || conn->peer_closed) {
            return false;
        }
    }
    return true;
}

void HttpContext::free() {
    /* http context can only be free'd after request and response were free'd */
    if (request.zobject || response.zobject) {
        return;
    }
    if (stream) {
        return;
    }

    HttpRequest *req = &request;
    HttpResponse *res = &response;
    if (req->path) {
        efree(req->path);
    }
    if (Z_TYPE(req->zdata) == IS_STRING) {
        zend_string_release(Z_STR(req->zdata));
    }
    if (req->chunked_body) {
        delete req->chunked_body;
    }
    if (req->h2_data_buffer) {
        delete req->h2_data_buffer;
    }
    if (res->reason) {
        efree(res->reason);
    }
    if (mt_parser) {
        multipart_parser_free(mt_parser);
        mt_parser = nullptr;
    }
    if (form_data_buffer) {
        delete form_data_buffer;
        form_data_buffer = nullptr;
    }
    delete this;
}

HttpContext *php_swoole_http_request_get_and_check_context(zval *zobject) {
    HttpContext *ctx = php_swoole_http_request_get_context(zobject);
    if (!ctx) {
        php_swoole_fatal_error(E_WARNING, "http request is unavailable (maybe it has been ended)");
    }
    return ctx;
}

HttpContext *php_swoole_http_response_get_and_check_context(zval *zobject) {
    HttpContext *ctx = php_swoole_http_response_get_context(zobject);
    if (!ctx || (ctx->end_ || ctx->detached)) {
        php_swoole_fatal_error(E_WARNING, "http response is unavailable (maybe it has been ended or detached)");
        return nullptr;
    }
    return ctx;
}

bool http_context_send_data(HttpContext *ctx, const char *data, size_t length) {
    Server *serv = (Server *) ctx->private_data;
    bool retval = serv->send(ctx->fd, (void *) data, length);
    if (!retval && swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD) {
        zval yield_data, return_value;
        ZVAL_STRINGL(&yield_data, data, length);
        php_swoole_server_send_yield(serv, ctx->fd, &yield_data, &return_value);
        return Z_BVAL_P(&return_value);
    }
    return retval;
}

static bool http_context_sendfile(HttpContext *ctx, const char *file, uint32_t l_file, off_t offset, size_t length) {
    Server *serv = (Server *) ctx->private_data;
    return serv->sendfile(ctx->fd, file, l_file, offset, length);
}

static bool http_context_disconnect(HttpContext *ctx) {
    Server *serv = (Server *) ctx->private_data;
    return serv->close(ctx->fd, 0);
}

bool swoole_http_server_onBeforeRequest(HttpContext *ctx) {
    Server *serv = (Server *) ctx->private_data;
    SwooleWG.worker->concurrency++;
    sw_atomic_add_fetch(&serv->gs->concurrency, 1);
    swoole_trace("serv->gs->concurrency=%u, max_concurrency=%u", serv->gs->concurrency, serv->gs->max_concurrency);
    if (SwooleWG.worker->concurrency > serv->worker_max_concurrency) {
        swoole_trace_log(SW_TRACE_COROUTINE,
                         "exceed worker_max_concurrency[%u] limit, request[%p] queued",
                         serv->worker_max_concurrency,
                         ctx);
        queued_http_contexts.push(ctx);
        return false;
    }

    return true;
}

void swoole_http_server_onAfterResponse(HttpContext *ctx) {
    ctx->onAfterResponse = nullptr;
    Server *serv = (Server *) ctx->private_data;
    SwooleWG.worker->concurrency--;
    sw_atomic_sub_fetch(&serv->gs->concurrency, 1);
    swoole_trace("serv->gs->concurrency=%u, max_concurrency=%u", serv->gs->concurrency, serv->gs->max_concurrency);
    if (!queued_http_contexts.empty()) {
        HttpContext *ctx = queued_http_contexts.front();
        swoole_trace(
            "[POP 1] concurrency=%u, ctx=%p, request=%p", SwooleWG.worker->concurrency, ctx, ctx->request.zobject);
        queued_http_contexts.pop();
        swoole_event_defer(
            [](void *private_data) {
                HttpContext *ctx = (HttpContext *) private_data;
                Server *serv = (Server *) ctx->private_data;
                zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) ctx->private_data_2;
                swoole_trace("[POP 2] ctx=%p, request=%p", ctx, ctx->request.zobject);
                http_server_process_request(serv, fci_cache, ctx);
                zval_ptr_dtor(ctx->request.zobject);
                zval_ptr_dtor(ctx->response.zobject);
            },
            ctx);
    }
}
