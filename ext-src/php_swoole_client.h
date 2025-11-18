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

#include "php_swoole_cxx.h"
#include "swoole_client.h"

enum ClientFlag {
    SW_FLAG_KEEP = 1u << 12,
    SW_FLAG_ASYNC = 1u << 10,
    SW_FLAG_SYNC = 1u << 11,
};

struct AsyncClientObject {
    zend::Callable *onConnect;
    zend::Callable *onReceive;
    zend::Callable *onClose;
    zend::Callable *onError;
    zend::Callable *onBufferFull;
    zend::Callable *onBufferEmpty;
#ifdef SW_USE_OPENSSL
    zend::Callable *onSSLReady;
#endif
    zval _zobject;
};

struct ClientObject {
    swoole::network::Client *cli;
#ifdef SWOOLE_SOCKETS_SUPPORT
    zval *zsocket;
#endif
    AsyncClientObject *async;
    zend_object std;
};

static inline ClientObject *php_swoole_client_fetch_object(zend_object *obj) {
    return reinterpret_cast<ClientObject *>(reinterpret_cast<char *>(obj) - swoole_client_handlers.offset);
}

static inline ClientObject *php_swoole_client_fetch_object(const zval *zobj) {
    return php_swoole_client_fetch_object(Z_OBJ_P(zobj));
}

static inline swoole::network::Client *php_swoole_client_get_cli(const zval *zobject) {
    return php_swoole_client_fetch_object(Z_OBJ_P(zobject))->cli;
}

static inline enum swSocketType php_swoole_client_get_type(long type) {
    return (enum swSocketType)(type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_FLAG_KEEP) & (~SW_SOCK_SSL));
}

swoole::network::Client *php_swoole_client_get_cli_safe(const zval *zobject);
void php_swoole_client_free(const zval *zobject, swoole::network::Client *cli);
void php_swoole_client_async_free_object(const ClientObject *client_obj);
bool php_swoole_client_check_setting(swoole::network::Client *cli, const zval *zset);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(const swoole::network::Client *cli, const zval *zset);
bool php_swoole_client_enable_ssl_encryption(swoole::network::Client *cli, zval *zobject);
#endif
