/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
*/

#ifdef _WIN32

#include "php_swoole_private.h"

int php_swoole_reactor_init() {
    // TODO 创建 IOCP 句柄
    return SW_OK;
}

void php_swoole_event_wait() {
    // TODO 进入 IOCP 循环
}

#endif
