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

#include "server.h"
#include "http.h"
#include "http2.h"
#include "websocket.h"
#include "mqtt.h"
#include "redis.h"

static int swPort_onRead_raw(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_check_length(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_check_eof(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_http(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_redis(swReactor *reactor, swListenPort *lp, swEvent *event);

void swPort_init(swListenPort *port)
{
    port->sock = 0;
    port->ssl = 0;

    //listen backlog
    port->backlog = SW_BACKLOG;
    //tcp keepalive
    port->tcp_keepcount = SW_TCP_KEEPCOUNT;
    port->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    port->tcp_keepidle = SW_TCP_KEEPIDLE;
    port->open_tcp_nopush = 1;

    port->protocol.package_length_type = 'N';
    port->protocol.package_length_size = 4;
    port->protocol.package_body_offset = 4;
    port->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

    port->socket_buffer_size = SwooleG.socket_buffer_size;

    char eof[] = SW_DATA_EOF;
    port->protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    memcpy(port->protocol.package_eof, eof, port->protocol.package_eof_len);
}

#ifdef SW_USE_OPENSSL
int swPort_enable_ssl_encrypt(swListenPort *ls)
{
    if (ls->ssl_option.cert_file == NULL || ls->ssl_option.key_file == NULL)
    {
        swWarn("SSL error, require ssl_cert_file and ssl_key_file");
        return SW_ERR;
    }
    ls->ssl_context = swSSL_get_context(&ls->ssl_option);
    if (ls->ssl_context == NULL)
    {
        swWarn("swSSL_get_context() error");
        return SW_ERR;
    }
    if (ls->ssl_option.client_cert_file
            && swSSL_set_client_certificate(ls->ssl_context, ls->ssl_option.client_cert_file,
                    ls->ssl_option.verify_depth) == SW_ERR)
    {
        swWarn("swSSL_set_client_certificate() error");
        return SW_ERR;
    }
    if (ls->open_http_protocol)
    {
        ls->ssl_config.http = 1;
    }
    if (ls->open_http2_protocol)
    {
        ls->ssl_config.http_v2 = 1;
        swSSL_server_http_advise(ls->ssl_context, &ls->ssl_config);
    }
    if (swSSL_server_set_cipher(ls->ssl_context, &ls->ssl_config) < 0)
    {
        swWarn("swSSL_server_set_cipher() error");
        return SW_ERR;
    }
    return SW_OK;
}
#endif

int swPort_listen(swListenPort *ls)
{
    int sock = ls->sock;
    int option = 1;

    //listen stream socket
    if (listen(sock, ls->backlog) < 0)
    {
        swSysWarn("listen(%s:%d, %d) failed", ls->host, ls->port, ls->backlog);
        return SW_ERR;
    }

#ifdef TCP_DEFER_ACCEPT
    if (ls->tcp_defer_accept)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const void*) &ls->tcp_defer_accept, sizeof(int)) != 0)
        {
            swSysWarn("setsockopt(TCP_DEFER_ACCEPT) failed");
        }
    }
#endif

#ifdef TCP_FASTOPEN
    if (ls->tcp_fastopen)
    {
        if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, (const void*) &ls->tcp_fastopen, sizeof(int)) != 0)
        {
            swSysWarn("setsockopt(TCP_FASTOPEN) failed");
        }
    }
#endif

#ifdef SO_KEEPALIVE
    if (ls->open_tcp_keepalive == 1)
    {
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &option, sizeof(option)) != 0)
        {
            swSysWarn("setsockopt(SO_KEEPALIVE) failed");
        }
#ifdef TCP_KEEPIDLE
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void*) &ls->tcp_keepidle, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &ls->tcp_keepinterval, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *) &ls->tcp_keepcount, sizeof(int));
#endif
    }
#endif

    ls->buffer_high_watermark = ls->socket_buffer_size * 0.8;
    ls->buffer_low_watermark = 0;

    return SW_OK;
}


void swPort_set_protocol(swListenPort *ls)
{
    //Thread mode must copy the data.
    //will free after onFinish
    if (ls->open_eof_check)
    {
        if (ls->protocol.package_eof_len > sizeof(ls->protocol.package_eof))
        {
            ls->protocol.package_eof_len = sizeof(ls->protocol.package_eof);
        }
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_eof;
    }
    else if (ls->open_length_check)
    {
        if (ls->protocol.package_length_type != '\0')
        {
            ls->protocol.get_package_length = swProtocol_get_package_length;
        }
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else if (ls->open_http_protocol)
    {
#ifdef SW_USE_HTTP2
        if (ls->open_http2_protocol && ls->open_websocket_protocol)
        {
            ls->protocol.get_package_length = swHttpMix_get_package_length;
            ls->protocol.get_package_length_size = swHttpMix_get_package_length_size;
            ls->protocol.onPackage = swHttpMix_dispatch_frame;
        }
        else if (ls->open_http2_protocol)
        {
            ls->protocol.get_package_length = swHttp2_get_frame_length;
            ls->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
            ls->protocol.onPackage = swReactorThread_dispatch;
        }
        else
#endif
        if (ls->open_websocket_protocol)
        {
            ls->protocol.get_package_length = swWebSocket_get_package_length;
            ls->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
            ls->protocol.onPackage = swWebSocket_dispatch_frame;
        }
        ls->onRead = swPort_onRead_http;
    }
    else if (ls->open_mqtt_protocol)
    {
        ls->protocol.get_package_length = swMqtt_get_package_length;
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else if (ls->open_redis_protocol)
    {
        ls->protocol.onPackage = swReactorThread_dispatch;
        ls->onRead = swPort_onRead_redis;
    }
    else
    {
        ls->onRead = swPort_onRead_raw;
    }
}

void swPort_clear_protocol(swListenPort *ls)
{
    ls->open_eof_check = 0;
    ls->open_length_check = 0;
    ls->open_http_protocol = 0;
    ls->open_websocket_protocol = 0;
#ifdef SW_USE_HTTP2
    ls->open_http2_protocol = 0;
#endif
    ls->open_mqtt_protocol = 0;
    ls->open_redis_protocol = 0;
}

static int swPort_onRead_raw(swReactor *reactor, swListenPort *port, swEvent *event)
{
    ssize_t n;
    swConnection *conn = event->socket;
    char *buffer = SwooleTG.buffer_stack->str;

    n = swConnection_recv(conn, buffer, SwooleTG.buffer_stack->size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysWarn("recv from connection#%d failed", event->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            goto _close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        _close_fd:
        swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
        return SW_OK;
    }
    else
    {
        return swReactorThread_dispatch(conn, buffer, n);
    }
}

static int swPort_onRead_check_length(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;

    swString *buffer = swServer_get_buffer(serv, event->fd);
    if (!buffer)
    {
        return SW_ERR;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0)
    {
        swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
    }

    return SW_OK;
}

/**
 * For Http Protocol
 */
static int swPort_onRead_http(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    swServer *serv = reactor->ptr;

    if (conn->websocket_status >= WEBSOCKET_STATUS_HANDSHAKE)
    {
        if (conn->http_upgrade == 0)
        {
            swHttpRequest_free(conn);
            conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
            conn->http_upgrade = 1;
        }
        return swPort_onRead_check_length(reactor, port, event);
    }

#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        _parse_frame: return swPort_onRead_check_length(reactor, port, event);
    }
#endif

    int n = 0;
    char *buf;
    int buf_len;

    swHttpRequest *request = NULL;
    swProtocol *protocol = &port->protocol;

    //new http request
    if (conn->object == NULL)
    {
        request = sw_malloc(sizeof(swHttpRequest));
        bzero(request, sizeof(swHttpRequest));
        conn->object = request;
    }
    else
    {
        request = (swHttpRequest *) conn->object;
    }

    if (!request->buffer)
    {
        request->buffer = swString_new(SW_HTTP_HEADER_MAX_SIZE);
        //alloc memory failed.
        if (!request->buffer)
        {
            swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
            return SW_ERR;
        }
    }

    swString *buffer = request->buffer;

    recv_data:
    buf = buffer->str + buffer->length;
    buf_len = buffer->size - buffer->length;

    n = swConnection_recv(conn, buf, buf_len, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysWarn("recv from connection#%d failed", event->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            goto close_fd;
        default:
            return SW_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
        swHttpRequest_free(conn);
        swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
        return SW_OK;
    }
    else
    {
        buffer->length += n;

        _parse:
        if (request->method == 0 && swHttpRequest_get_protocol(request) < 0)
        {
            if (request->excepted == 0 && request->buffer->length < SW_HTTP_HEADER_MAX_SIZE)
            {
                return SW_OK;
            }
            swoole_error_log(SW_LOG_TRACE, SW_ERROR_HTTP_INVALID_PROTOCOL, "get protocol failed");
#ifdef SW_USE_HTTP2
            _bad_request:
#endif
#ifdef SW_HTTP_BAD_REQUEST_PACKET
            swConnection_send(conn, SW_STRL(SW_HTTP_BAD_REQUEST_PACKET), 0);
#endif
            goto close_fd;
        }

        if (request->method > SW_HTTP_PRI)
        {
            swWarn("method no support");
            goto close_fd;
        }
#ifdef SW_USE_HTTP2
        else if (request->method == SW_HTTP_PRI)
        {
            if (unlikely(!port->open_http2_protocol))
            {
                goto _bad_request;
            }

            conn->http2_stream = 1;
            swHttp2_send_setting_frame(protocol, conn);
            if (n == sizeof(SW_HTTP2_PRI_STRING) - 1)
            {
                swHttpRequest_free(conn);
                return SW_OK;
            }
            swString *buffer = swServer_get_buffer(serv, event->fd);
            if (!buffer)
            {
                goto close_fd;
            }
            swString_append_ptr(buffer, buf + (sizeof(SW_HTTP2_PRI_STRING) - 1), n - (sizeof(SW_HTTP2_PRI_STRING) - 1));
            swHttpRequest_free(conn);
            conn->skip_recv = 1;
            goto _parse_frame;
        }
#endif
        //http header is not the end
        if (request->header_length == 0)
        {
            if (swHttpRequest_get_header_length(request) < 0)
            {
                if (buffer->size == buffer->length)
                {
                    swWarn("[2]http header is too long");
                    goto close_fd;
                }
                else
                {
                    goto recv_data;
                }
            }
        }

        //http body
        if (request->content_length == 0)
        {
            swTraceLog(SW_TRACE_SERVER, "content-length=%u, keep-alive=%d", request->content_length, request->keep_alive);
            // content length field not found
            if (swHttpRequest_get_header_info(request) < 0)
            {
                /* the request is really no body */
                if (buffer->length >= request->header_length)
                {
                    /**
                     * send static file content directly in the reactor thread
                     */
                    if (!(serv->enable_static_handler && swHttpRequset_static_handler(serv, request, conn)))
                    {
                        /**
                         * dynamic request, dispatch to worker
                         */
                        swReactorThread_dispatch(conn, buffer->str, request->header_length);
                        /**
                         * http pipeline, multi request
                         */
                        if (conn->active && buffer->length > request->header_length)
                        {
                            swString_pop_front(buffer, request->header_length);
                            swHttpRequest_clean(request);
                            goto _parse;
                        }
                    }
                    swHttpRequest_free(conn);
                    return SW_OK;
                }
                else if (buffer->size == buffer->length)
                {
                    swWarn("[0]http header is too long");
                    goto close_fd;
                }
                /* wait more data */
                else
                {
                    goto recv_data;
                }
            }
            else if (request->content_length > (protocol->package_max_length - request->header_length))
            {
                swWarn("Content-Length is too big, MaxSize=[%d]", protocol->package_max_length - request->header_length);
                goto close_fd;
            }
        }

        //total length
        uint32_t request_size = request->header_length + request->content_length;
        if (request_size > buffer->size && swString_extend(buffer, request_size) < 0)
        {
            goto close_fd;
        }

        //discard the redundant data
        if (buffer->length > request_size)
        {
            buffer->length = request_size;
        }

        if (buffer->length == request_size)
        {
            swReactorThread_dispatch(conn, buffer->str, buffer->length);
            swHttpRequest_free(conn);
        }
        else
        {
#ifdef SW_HTTP_100_CONTINUE
            //Expect: 100-continue
            if (swHttpRequest_has_expect_header(request))
            {
                swSendData _send;
                _send.data = "HTTP/1.1 100 Continue\r\n\r\n";
                _send.length = strlen(_send.data);

                int send_times = 0;
                direct_send:
                n = swConnection_send(conn, _send.data, _send.length, 0);
                if (n < _send.length)
                {
                    _send.data += n;
                    _send.length -= n;
                    send_times++;
                    if (send_times < 10)
                    {
                        goto direct_send;
                    }
                    else
                    {
                        swWarn("send http header failed");
                    }
                }
            }
            else
            {
                swTraceLog(
                    SW_TRACE_SERVER, "PostWait: request->content_length=%d, buffer->length=%zu, request->header_length=%d\n",
                    request->content_length, buffer->length, request->header_length
                );
            }
#endif
            goto recv_data;
        }
    }
    return SW_OK;
}

static int swPort_onRead_redis(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;
    swServer *serv = reactor->ptr;

    swString *buffer = swServer_get_buffer(serv, event->fd);
    if (!buffer)
    {
        return SW_ERR;
    }

    if (swRedis_recv(protocol, conn, buffer) < 0)
    {
        swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
    }

    return SW_OK;
}

static int swPort_onRead_check_eof(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;
    swServer *serv = reactor->ptr;

    swString *buffer = swServer_get_buffer(serv, event->fd);
    if (!buffer)
    {
        return SW_ERR;
    }

    if (swProtocol_recv_check_eof(protocol, conn, buffer) < 0)
    {
        swReactor_getHandle(reactor, 0, SW_FD_CLOSE)(reactor, event);
    }

    return SW_OK;
}

void swPort_free(swListenPort *port)
{
#ifdef SW_USE_OPENSSL
    if (port->ssl)
    {
        if (port->ssl_context)
        {
            swSSL_free_context(port->ssl_context);
        }
        sw_free(port->ssl_option.cert_file);
        sw_free(port->ssl_option.key_file);
        if (port->ssl_option.client_cert_file)
        {
            sw_free(port->ssl_option.client_cert_file);
        }
    }
#endif

    close(port->sock);

    //remove unix socket file
    if (port->type == SW_SOCK_UNIX_STREAM || port->type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(port->host);
    }
}

