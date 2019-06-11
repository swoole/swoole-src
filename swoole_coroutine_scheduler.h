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

void swoole_coroutine_scheduler_init(int module_number);

PHP_METHOD(swoole_coroutine_scheduler, set);
PHP_METHOD(swoole_coroutine_scheduler, exists);
PHP_METHOD(swoole_coroutine_scheduler, yield);
PHP_METHOD(swoole_coroutine_scheduler, resume);
PHP_METHOD(swoole_coroutine_scheduler, stats);
PHP_METHOD(swoole_coroutine_scheduler, getCid);
PHP_METHOD(swoole_coroutine_scheduler, getPcid);
PHP_METHOD(swoole_coroutine_scheduler, getContext);
PHP_METHOD(swoole_coroutine_scheduler, getBackTrace);
PHP_METHOD(swoole_coroutine_scheduler, list);
PHP_METHOD(swoole_coroutine_scheduler, disableScheduler);
PHP_METHOD(swoole_coroutine_scheduler, enableScheduler);
