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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"

// clang-format off
BEGIN_EXTERN_C()
#include "stubs/php_swoole_coroutine_system_arginfo.h"
END_EXTERN_C()
// clang-format on

SW_EXTERN_C_BEGIN
PHP_METHOD(swoole_coroutine_system, exec);
PHP_METHOD(swoole_coroutine_system, sleep);
PHP_METHOD(swoole_coroutine_system, fread);
PHP_METHOD(swoole_coroutine_system, fgets);
PHP_METHOD(swoole_coroutine_system, fwrite);
PHP_METHOD(swoole_coroutine_system, statvfs);
PHP_METHOD(swoole_coroutine_system, getaddrinfo);
PHP_METHOD(swoole_coroutine_system, readFile);
PHP_METHOD(swoole_coroutine_system, writeFile);
PHP_METHOD(swoole_coroutine_system, wait);
PHP_METHOD(swoole_coroutine_system, waitPid);
PHP_METHOD(swoole_coroutine_system, waitSignal);
PHP_METHOD(swoole_coroutine_system, waitEvent);
SW_EXTERN_C_END
