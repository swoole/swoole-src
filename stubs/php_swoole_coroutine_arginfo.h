/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: a2d32f239de662193ca1b9e663a7f8becfd635ff */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_create, 0, 1, MAY_BE_LONG|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO(0, func, IS_CALLABLE, 0)
	ZEND_ARG_VARIADIC_TYPE_INFO(0, param, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_defer, 0, 1, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_set, 0, 1, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, options, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_getOptions, 0, 0, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_exists, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, cid, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_yield, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_cancel arginfo_class_Swoole_Coroutine_exists

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_join, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, cid_array, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "-1")
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_isCanceled arginfo_class_Swoole_Coroutine_yield

#define arginfo_class_Swoole_Coroutine_suspend arginfo_class_Swoole_Coroutine_yield

#define arginfo_class_Swoole_Coroutine_resume arginfo_class_Swoole_Coroutine_exists

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_stats, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_getCid, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_getuid arginfo_class_Swoole_Coroutine_getCid

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_getPcid, 0, 0, MAY_BE_BOOL|MAY_BE_LONG)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, cid, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_getContext, 0, 0, Swoole\\Coroutine\\Context, MAY_BE_BOOL|MAY_BE_NULL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, cid, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_getBackTrace, 0, 0, MAY_BE_ARRAY|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, cid, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_LONG, 0, "DEBUG_BACKTRACE_PROVIDE_OBJECT")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, limit, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_printBackTrace, 0, 0, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, cid, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_LONG, 0, "DEBUG_BACKTRACE_PROVIDE_OBJECT")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, limit, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Coroutine_getElapsed, 0, 0, MAY_BE_LONG|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, cid, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_getStackUsage arginfo_class_Swoole_Coroutine_getPcid

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Coroutine_list, 0, 0, Swoole\\Coroutine\\Iterator, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_listCoroutines arginfo_class_Swoole_Coroutine_list

#define arginfo_class_Swoole_Coroutine_enableScheduler arginfo_class_Swoole_Coroutine_yield

#define arginfo_class_Swoole_Coroutine_disableScheduler arginfo_class_Swoole_Coroutine_yield

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_ExitException_getFlags, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_ExitException_getStatus arginfo_class_Swoole_Coroutine_getCid
