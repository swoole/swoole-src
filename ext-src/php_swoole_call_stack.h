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
  | Author: Yurun  <yurun@yurunsoft.com>                                 |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

#ifdef ZEND_CHECK_STACK_LIMIT
#define HOOK_PHP_CALL_STACK(callback)                                                                                  \
    void *__stack_limit = EG(stack_limit);                                                                             \
    void *__stack_base = EG(stack_base);                                                                               \
    EG(stack_base) = (void *) 0;                                                                                       \
    EG(stack_limit) = (void *) 0;                                                                                      \
    callback EG(stack_limit) = __stack_limit;                                                                          \
    EG(stack_base) = __stack_base;
#else
#define HOOK_PHP_CALL_STACK(callback) callback
#endif
