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

#include "php_swoole_cxx.h"
#include "client.h"

void php_swoole_client_free(zval *zobject, swClient *cli);
swClient* php_swoole_client_new(zval *zobject, char *host, int host_len, int port);
void php_swoole_client_check_setting(swClient *cli, zval *zset);
#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(swClient *cli, zval *zset);
#endif
