/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: e52a0cdfee0e3458178486d224789156223f91c5 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_timer_set, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_timer_tick, 0, 2, MAY_BE_FALSE|MAY_BE_LONG)
	ZEND_ARG_TYPE_INFO(0, ms, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
	ZEND_ARG_VARIADIC_TYPE_INFO(0, params, IS_MIXED, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_timer_after arginfo_swoole_timer_tick

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_timer_exists, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, timer_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_timer_info, 0, 1, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, timer_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_timer_stats, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_swoole_timer_list, 0, 0, Swoole\\Timer\\Iterator, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_timer_clear arginfo_swoole_timer_exists

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_timer_clear_all, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()
