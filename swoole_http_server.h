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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#pragma once

#include "swoole_server.h"
#include "swoole_http.h"

int swoole_websocket_onMessage(swServer *serv, swEventData *req);
int swoole_websocket_onHandshake(swServer *serv, swListenPort *port, http_context *ctx);
void swoole_websocket_onOpen(http_context *ctx);
void swoole_websocket_onRequest(http_context *ctx);
bool swoole_websocket_handshake(http_context *ctx);

