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

#pragma once

#include "php_swoole.h"

#ifdef ZEND_CHECK_STACK_LIMIT
    #include "thirdparty/php83/Zend/zend_call_stack.h"
#endif

#ifdef ZEND_CHECK_STACK_LIMIT
    #define HOOK_PHP_CALL_STACK(exp) \
        zend_call_stack __stack; \
        zend_call_stack_get(&__stack); \
        auto __stack_base = EG(stack_base); \
        auto __stack_limit = EG(stack_limit); \
        EG(stack_base) = __stack.base; \
        EG(stack_limit) = zend_call_stack_limit(__stack.base, __stack.max_size, EG(reserved_stack_size)); \
        exp \
        EG(stack_base) = __stack_base; \
        EG(stack_limit) = __stack_limit;
#else
    #define HOOK_PHP_CALL_STACK(exp) exp
#endif
