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

static sw_inline ClientObject *php_swoole_client_fetch_object(zend_object *obj) {
    return (ClientObject *) ((char *) obj - swoole_client_handlers.offset);
}

static sw_inline ClientObject *php_swoole_client_fetch_object(zval *zobj) {
    return php_swoole_client_fetch_object(Z_OBJ_P(zobj));
}

static sw_inline swoole::network::Client *php_swoole_client_get_cli(zval *zobject) {
    return php_swoole_client_fetch_object(Z_OBJ_P(zobject))->cli;
}

swoole::network::Client *php_swoole_client_get_cli_safe(zval *zobject);
void php_swoole_client_free(zval *zobject, swoole::network::Client *cli);
void php_swoole_client_async_free_object(ClientObject *client_obj);
bool php_swoole_client_check_setting(swoole::network::Client *cli, zval *zset);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swoole::network::Client *cli, zval *zset);
bool php_swoole_client_enable_ssl_encryption(swoole::network::Client *cli, zval *zobject);
#endif
