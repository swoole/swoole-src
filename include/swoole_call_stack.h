#pragma once

#include "swoole.h"

#ifdef ZEND_CHECK_STACK_LIMIT
    #define HOOK_PHP_CALL_STACK(exp) \
        swoole::call_stack __stack; \
        swoole::call_stack_get(&__stack); \
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

namespace swoole {
    typedef struct _swoole_call_stack {
        void *base;
        size_t max_size;
    } call_stack;

    bool call_stack_get(call_stack *stack);
}
