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
#include "swoole_http2.h"

bool swoole_http_server_onBeforeRequest(swoole::http::Context *ctx);
void swoole_http_server_onAfterResponse(swoole::http::Context *ctx);

int swoole_websocket_onMessage(swoole::Server *serv, swoole::RecvData *req);
int swoole_websocket_onHandshake(swoole::Server *serv, swoole::ListenPort *port, swoole::http::Context *ctx);
void swoole_websocket_onBeforeHandshakeResponse(swoole::http::Context *ctx);
void swoole_websocket_onOpen(swoole::http::Context *ctx);
void swoole_websocket_onRequest(swoole::http::Context *ctx);
bool swoole_websocket_handshake(swoole::http::Context *ctx);

int swoole_http2_server_parse(swoole::http2::Session *client, const char *buf);
int swoole_http2_server_onReceive(swoole::Server *serv, swoole::Connection *conn, swoole::RecvData *req);
void swoole_http2_server_session_free(swoole::Connection *conn);
int swoole_http2_server_ping(swoole::http::Context *ctx);
int swoole_http2_server_goaway(swoole::http::Context *ctx,
                               zend_long error_code,
                               const char *debug_data,
                               size_t debug_data_len);

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, const char *value) {
    zval tmp;
    ZVAL_STRING(&tmp, value);
    zend_hash_add_new(ht, key, &tmp);
}

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, const char *value, size_t length) {
    zval tmp;
    ZVAL_STRINGL(&tmp, value, length);
    zend_hash_add_new(ht, key, &tmp);
}

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, zend_long value) {
    zval tmp;
    ZVAL_LONG(&tmp, value);
    zend_hash_add_new(ht, key, &tmp);
}

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, double value) {
    zval tmp;
    ZVAL_DOUBLE(&tmp, value);
    zend_hash_add_new(ht, key, &tmp);
}

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, zend_string *value) {
    zval tmp;
    ZVAL_STR(&tmp, value);
    zend_hash_add_new(ht, key, &tmp);
}

static inline void http_server_add_server_array(HashTable *ht, zend_string *key, zval *value) {
    zend_hash_add_new(ht, key, value);
}

static inline void http_server_set_object_fd_property(zend_object *object, zend_class_entry *ce, long fd) {
    zval *zv = zend_hash_find(&ce->properties_info, SW_ZSTR_KNOWN(SW_ZEND_STR_FD));
    zend_property_info *property_info = (zend_property_info *) Z_PTR_P(zv);
    zval *property = OBJ_PROP(object, property_info->offset);
    ZVAL_LONG(property, fd);
}
