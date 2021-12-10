ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_set, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_cancel, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_join, 0, 0, 1)
    ZEND_ARG_INFO(0, cid_array)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getContext, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_printBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getPcid, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getElapsed, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getStackUsage, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Coroutine_getExecuteTime, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_create           arginfo_swoole_coroutine_create
#define arginfo_class_Swoole_Coroutine_defer            arginfo_swoole_coroutine_defer
#define arginfo_class_Swoole_Coroutine_set              arginfo_swoole_coroutine_set
#define arginfo_class_Swoole_Coroutine_getOptions       arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_exists           arginfo_swoole_coroutine_exists
#define arginfo_class_Swoole_Coroutine_yield            arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_cancel           arginfo_swoole_coroutine_cancel
#define arginfo_class_Swoole_Coroutine_join             arginfo_swoole_coroutine_join
#define arginfo_class_Swoole_Coroutine_isCanceled       arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_suspend          arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_resume           arginfo_swoole_coroutine_resume
#define arginfo_class_Swoole_Coroutine_stats            arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_getCid           arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_getuid           arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_getPcid          arginfo_swoole_coroutine_getPcid
#define arginfo_class_Swoole_Coroutine_getContext       arginfo_swoole_coroutine_getContext
#define arginfo_class_Swoole_Coroutine_getBackTrace     arginfo_swoole_coroutine_getBackTrace
#define arginfo_class_Swoole_Coroutine_printBackTrace   arginfo_swoole_coroutine_printBackTrace
#define arginfo_class_Swoole_Coroutine_getElapsed       arginfo_swoole_coroutine_getElapsed
#define arginfo_class_Swoole_Coroutine_getStackUsage    arginfo_swoole_coroutine_getStackUsage
#define arginfo_class_Swoole_Coroutine_list             arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_listCoroutines   arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_enableScheduler  arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_disableScheduler arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_Coroutine_getExecuteTime   arginfo_swoole_coroutine_void

#define arginfo_class_Swoole_ExitException_getFlags  arginfo_swoole_coroutine_void
#define arginfo_class_Swoole_ExitException_getStatus arginfo_swoole_coroutine_void
