/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2017 The Swoole Group                             |
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

#include "swoole.h"
#include "swoole_proxy.h"
#include "swoole_client.h"
#include "swoole_log.h"

using swoole::Socks5Proxy;

const char *swSocks5_strerror(int code) {
    switch (code) {
    case 0x01:
        return "General failure";
    case 0x02:
        return "Connection not allowed by ruleset";
    case 0x03:
        return "Network unreachable";
    case 0x04:
        return "Host unreachable";
    case 0x05:
        return "Connection refused by destination host";
    case 0x06:
        return "TTL expired";
    case 0x07:
        return "command not supported / protocol error";
    case 0x08:
        return "address type not supported";
    default:
        return "Unknown error";
    }
}

int swSocks5_connect(swoole::network::Client *cli, char *recv_data, int length) {
    Socks5Proxy *ctx = cli->socks5_proxy;
    char *buf = ctx->buf;
    uchar version, status, result, method;

    if (ctx->state == SW_SOCKS5_STATE_HANDSHAKE) {
        version = recv_data[0];
        method = recv_data[1];
        if (version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        if (method != ctx->method) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method not supported");
            return SW_ERR;
        }
        // authenticate request
        if (method == SW_SOCKS5_METHOD_AUTH) {
            buf[0] = 0x01;
            buf[1] = ctx->username.length();

            buf += 2;
            memcpy(buf, ctx->username.c_str(), ctx->username.length());
            buf += ctx->username.length();
            buf[0] = ctx->password.length();
            memcpy(buf + 1, ctx->password.c_str(), ctx->password.length());

            ctx->state = SW_SOCKS5_STATE_AUTH;

            return cli->send(cli, ctx->buf, ctx->username.length() + ctx->password.length() + 3, 0);
        }
        // send connect request
        else {
        _send_connect_request:
            buf[0] = SW_SOCKS5_VERSION_CODE;
            buf[1] = 0x01;
            buf[2] = 0x00;

            ctx->state = SW_SOCKS5_STATE_CONNECT;

            if (ctx->dns_tunnel) {
                buf[3] = 0x03;
                buf[4] = ctx->l_target_host;
                buf += 5;
                memcpy(buf, ctx->target_host, ctx->l_target_host);
                buf += ctx->l_target_host;
                *(uint16_t *) buf = htons(ctx->target_port);
                return cli->send(cli, ctx->buf, ctx->l_target_host + 7, 0);
            } else {
                buf[3] = 0x01;
                buf += 4;
                *(uint32_t *) buf = htons(ctx->l_target_host);
                buf += 4;
                *(uint16_t *) buf = htons(ctx->target_port);
                return cli->send(cli, ctx->buf, ctx->l_target_host + 7, 0);
            }
        }
    } else if (ctx->state == SW_SOCKS5_STATE_AUTH) {
        version = recv_data[0];
        status = recv_data[1];
        if (version != 0x01) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        if (status != 0) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS username/password authentication failed");
            return SW_ERR;
        }
        goto _send_connect_request;
    } else if (ctx->state == SW_SOCKS5_STATE_CONNECT) {
        version = recv_data[0];
        if (version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return SW_ERR;
        }
        result = recv_data[1];
#if 0
        uchar reg = recv_data[2];
        uchar type = recv_data[3];
        uint32_t ip = *(uint32_t *) (recv_data + 4);
        uint16_t port = *(uint16_t *) (recv_data + 8);
#endif
        if (result == 0) {
            ctx->state = SW_SOCKS5_STATE_READY;
        } else {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SOCKS5_SERVER_ERROR,
                             "Socks5 server error, reason :%s",
                             swSocks5_strerror(result));
        }
        return result;
    }
    return SW_OK;
}
