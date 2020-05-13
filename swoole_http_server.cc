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

#include "swoole_http_server.h"
#include "websocket.h"

#include "main/rfc1867.h"

#ifdef SW_USE_HTTP2
#include "http2.h"
#endif

using namespace swoole;
using swoole::coroutine::Socket;

swString *swoole_http_buffer;
#ifdef SW_HAVE_COMPRESSION
/* not only be used by zlib but also be used by br */
swString *swoole_zlib_buffer;
#endif
swString *swoole_http_form_data_buffer;

zend_class_entry *swoole_http_server_ce;
zend_object_handlers swoole_http_server_handlers;

static bool http_context_send_data(http_context* ctx, const char *data, size_t length);
static bool http_context_sendfile(http_context* ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
static bool http_context_disconnect(http_context* ctx);

int php_swoole_http_onReceive(swServer *serv, swEventData *req)
{
    int fd = req->info.fd;
    int server_fd = req->info.server_fd;

    swConnection *conn = swServer_connection_verify_no_ssl(serv, fd);
    if (!conn)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_NOT_EXIST, "connection[%d] is closed", fd);
        return SW_ERR;
    }

    swListenPort *port = (swListenPort *) serv->connection_list[server_fd].object;
    //other server port
    if (!port->open_http_protocol)
    {
        return php_swoole_onReceive(serv, req);
    }
    //websocket client
    if (conn->websocket_status == WEBSOCKET_STATUS_ACTIVE)
    {
        return swoole_websocket_onMessage(serv, req);
    }
#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        return swoole_http2_server_onFrame(serv, conn, req);
    }
#endif

    http_context *ctx = swoole_http_context_new(fd);
    swoole_http_server_init_context(serv, ctx);

    zval *zdata = &ctx->request.zdata;
    php_swoole_get_recv_data(serv, zdata, req);

    swTraceLog(SW_TRACE_SERVER, "http request from %d with %d bytes: <<EOF\n%.*s\nEOF", fd, (int) Z_STRLEN_P(zdata), (int) Z_STRLEN_P(zdata), Z_STRVAL_P(zdata));

    zval args[2], *zrequest_object = &args[0], *zresponse_object = &args[1];
    args[0] = *ctx->request.zobject;
    args[1] = *ctx->response.zobject;

    swoole_http_parser *parser = &ctx->parser;
    parser->data = ctx;
    swoole_http_parser_init(parser, PHP_HTTP_REQUEST);

    size_t parsed_n = swoole_http_requset_parse(ctx, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    if (ctx->parser.state == s_dead)
    {
#ifdef SW_HTTP_BAD_REQUEST_PACKET
        ctx->send(ctx, SW_STRL(SW_HTTP_BAD_REQUEST_PACKET));
#endif
        ctx->close(ctx);
        swNotice("request is illegal and it has been discarded, %ld bytes unprocessed", Z_STRLEN_P(zdata) - parsed_n);
        goto _dtor_and_return;
    }

    do {
        zval *zserver = ctx->request.zserver;
        swConnection *serv_sock = swServer_connection_get(serv, conn->server_fd);
        if (serv_sock)
        {
            add_assoc_long(zserver, "server_port", swSocket_get_port(serv_sock->socket_type, &serv_sock->info));
        }
        add_assoc_long(zserver, "remote_port", swSocket_get_port(conn->socket_type, &conn->info));
        add_assoc_string(zserver, "remote_addr", (char *) swSocket_get_ip(conn->socket_type, &conn->info));
        add_assoc_long(zserver, "master_time", conn->last_time);
    } while (0);

    // begin to check and call registerd callback
    do {
        zend_fcall_info_cache *fci_cache = NULL;

        if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
        {
            fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onHandShake);
            if (fci_cache == NULL)
            {
                swoole_websocket_onHandshake(serv, port, ctx);
                goto _dtor_and_return;
            }
            else
            {
                conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
                ctx->upgrade = 1;
            }
        }
        else
        {
            fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onRequest);
            if (fci_cache == NULL)
            {
                swoole_websocket_onRequest(ctx);
                goto _dtor_and_return;
            }
        }

        if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, NULL, SwooleG.enable_coroutine)))
        {
            php_swoole_error(E_WARNING, "%s->onRequest handler error", ZSTR_VAL(swoole_http_server_ce->name));
    #ifdef SW_HTTP_SERVICE_UNAVAILABLE_PACKET
            ctx->send(ctx, SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET));
    #endif
            ctx->close(ctx);
        }
    } while (0);

    _dtor_and_return:
    zval_ptr_dtor(zrequest_object);
    zval_ptr_dtor(zresponse_object);

    return SW_OK;
}

void php_swoole_http_onClose(swServer *serv, swDataHead *ev)
{
    swConnection *conn = swWorker_get_connection(serv, ev->fd);
    if (!conn)
    {
        return;
    }
    php_swoole_onClose(serv, ev);
#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        swoole_http2_server_session_free(conn);
    }
#endif
}

void php_swoole_http_server_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY_EX(swoole_http_server, "Swoole\\Http\\Server", "swoole_http_server", NULL, NULL, swoole_server);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_server, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_server, sw_zend_class_unset_property_deny);

    zend_declare_property_null(swoole_http_server_ce, ZEND_STRL("onRequest"), ZEND_ACC_PRIVATE);
}

http_context* swoole_http_context_new(int fd)
{
    http_context *ctx = (http_context *) ecalloc(1, sizeof(http_context));

    zval *zrequest_object = &ctx->request._zobject;
    ctx->request.zobject = zrequest_object;
    object_init_ex(zrequest_object, swoole_http_request_ce);
    php_swoole_http_request_set_context(zrequest_object, ctx);

    zval *zresponse_object = &ctx->response._zobject;
    ctx->response.zobject = zresponse_object;
    object_init_ex(zresponse_object, swoole_http_response_ce);
    php_swoole_http_response_set_context(zresponse_object, ctx);

    zend_update_property_long(swoole_http_request_ce, zrequest_object, ZEND_STRL("fd"), fd);
    zend_update_property_long(swoole_http_response_ce, zresponse_object, ZEND_STRL("fd"), fd);

#if PHP_MEMORY_DEBUG
    php_vmstat.new_http_request ++;
#endif

    swoole_http_init_and_read_property(swoole_http_request_ce, zrequest_object, &ctx->request.zserver, ZEND_STRL("server"));
    swoole_http_init_and_read_property(swoole_http_request_ce, zrequest_object, &ctx->request.zheader, ZEND_STRL("header"));
    ctx->fd = fd;

    return ctx;
}

void swoole_http_server_init_context(swServer *serv, http_context *ctx)
{
    ctx->parse_cookie = serv->http_parse_cookie;
    ctx->parse_body = serv->http_parse_post;
    ctx->parse_files = serv->http_parse_files;
#ifdef SW_HAVE_COMPRESSION
    ctx->enable_compression = serv->http_compression;
    ctx->compression_level = serv->http_compression_level;
#endif
    ctx->private_data = serv;
    ctx->upload_tmp_dir = serv->upload_tmp_dir;
    ctx->send = http_context_send_data;
    ctx->sendfile = http_context_sendfile;
    ctx->close = http_context_disconnect;
}

void swoole_http_context_copy(http_context *src, http_context *dst)
{
    dst->parse_cookie = src->parse_cookie;
    dst->parse_body = src->parse_body;
    dst->parse_files = src->parse_files;
#ifdef SW_HAVE_COMPRESSION
    dst->enable_compression = src->enable_compression;
    dst->compression_level = src->compression_level;
#endif
    dst->private_data = src->private_data;
    dst->upload_tmp_dir = src->upload_tmp_dir;
    dst->send = src->send;
    dst->sendfile = src->sendfile;
    dst->close = src->close;
}

void swoole_http_context_free(http_context *ctx)
{
    /* http context can only be free'd after request and response were free'd */
    if (ctx->request.zobject || ctx->response.zobject)
    {
        return;
    }
#ifdef SW_USE_HTTP2
    if (ctx->stream)
    {
        return;
    }
#endif

    http_request *req = &ctx->request;
    http_response *res = &ctx->response;
    if (req->path)
    {
        efree(req->path);
    }
    if (Z_TYPE(req->zdata) == IS_STRING)
    {
        zend_string_release(Z_STR(req->zdata));
    }
    if (req->chunked_body)
    {
        swString_free(req->chunked_body);
    }
#ifdef SW_USE_HTTP2
    if (req->h2_data_buffer)
    {
        swString_free(req->h2_data_buffer);
    }
#endif
    if (res->reason)
    {
        efree(res->reason);
    }
    efree(ctx);
}

void php_swoole_http_server_init_global_variant()
{
    swoole_http_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_buffer)
    {
        php_swoole_fatal_error(E_ERROR, "[swoole_http_buffer] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
        return;
    }

    swoole_http_form_data_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_http_form_data_buffer)
    {
        php_swoole_fatal_error(E_ERROR, "[swoole_http_form_data_buffer] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
        return;
    }

    //for is_uploaded_file and move_uploaded_file
    if (!SG(rfc1867_uploaded_files))
    {
        ALLOC_HASHTABLE(SG(rfc1867_uploaded_files));
        zend_hash_init(SG(rfc1867_uploaded_files), 8, NULL, NULL, 0);
    }
}

http_context* php_swoole_http_request_get_and_check_context(zval *zobject)
{
    http_context *ctx = php_swoole_http_request_get_context(zobject);
    if (!ctx)
    {
        php_swoole_fatal_error(E_WARNING, "http request is unavailable (maybe it has been ended)");
    }
    return ctx;
}

http_context* php_swoole_http_response_get_and_check_context(zval *zobject)
{
    http_context *ctx = php_swoole_http_response_get_context(zobject);
    if (!ctx || (ctx->end || ctx->detached))
    {
        php_swoole_fatal_error(E_WARNING, "http response is unavailable (maybe it has been ended or detached)");
        return NULL;
    }
    return ctx;
}

bool http_context_send_data(http_context* ctx, const char *data, size_t length)
{
    swServer *serv = (swServer *) ctx->private_data;
    ssize_t ret = serv->send(serv, ctx->fd, (void*) data, length);
    if (ret < 0 && swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD)
    {
        zval yield_data, return_value;
        ZVAL_STRINGL(&yield_data, data, length);
        php_swoole_server_send_yield(serv, ctx->fd, &yield_data, &return_value);
        ret = Z_BVAL_P(&return_value) ? SW_OK : SW_ERR;
    }
    return ret == SW_OK;
}

static bool http_context_sendfile(http_context* ctx, const char *file, uint32_t l_file, off_t offset, size_t length)
{
    swServer *serv = (swServer *) ctx->private_data;
    return serv->sendfile(serv, ctx->fd, file, l_file, offset, length) == SW_OK;
}

static bool http_context_disconnect(http_context* ctx)
{
    swServer *serv = (swServer *) ctx->private_data;
    return serv->close(serv, ctx->fd, 0) == SW_OK;
}
