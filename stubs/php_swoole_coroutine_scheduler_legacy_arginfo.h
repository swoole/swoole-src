ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_add, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_parallel, 0, 0, 1)
    ZEND_ARG_INFO(0, n)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_scheduler_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Scheduler_add        arginfo_swoole_coroutine_scheduler_add
#define arginfo_class_Swoole_Coroutine_Scheduler_parallel   arginfo_swoole_coroutine_scheduler_parallel
#define arginfo_class_Swoole_Coroutine_Scheduler_set        arginfo_swoole_coroutine_scheduler_set
#define arginfo_class_Swoole_Coroutine_Scheduler_getOptions arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Scheduler_start      arginfo_swoole_void
