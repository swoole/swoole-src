/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#pragma once

#include "php_swoole_server.h"
#include "php_swoole_http.h"

#include "swoole_http.h"
#include "swoole_websocket.h"
#include "swoole_mime_type.h"

#ifdef SW_USE_HTTP2
#include "swoole_http2.h"
#endif

int swoole_websocket_onMessage(swoole::Server *serv, swoole::RecvData *req);
int swoole_websocket_onHandshake(swoole::Server *serv, swoole::ListenPort *port, swoole::http::Context *ctx);
void swoole_websocket_onOpen(swoole::http::Context *ctx);
void swoole_websocket_onRequest(swoole::http::Context *ctx);
bool swoole_websocket_handshake(swoole::http::Context *ctx);

#ifdef SW_USE_HTTP2

int swoole_http2_server_onReceive(swoole::Server *serv, swoole::Connection *conn, swoole::RecvData *req);
int swoole_http2_server_parse(swoole::http2::Session *client, const char *buf);
void swoole_http2_server_session_free(swoole::Connection *conn);
int swoole_http2_server_ping(swoole::http::Context *ctx);
int swoole_http2_server_goaway(swoole::http::Context *ctx, zend_long error_code, const char *debug_data, size_t debug_data_len);

#endif
