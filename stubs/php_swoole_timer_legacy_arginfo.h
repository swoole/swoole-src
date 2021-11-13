/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 9e026d4e6984a11ab02a32f3bbd05542ccd37d97 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_set, 0, 0, 1)
	ZEND_ARG_INFO(0, settings)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_tick, 0, 0, 2)
	ZEND_ARG_INFO(0, ms)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

#define arginfo_swoole_timer_after arginfo_swoole_timer_tick

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_exists, 0, 0, 1)
	ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

#define arginfo_swoole_timer_info arginfo_swoole_timer_exists

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_stats, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_timer_list arginfo_swoole_timer_stats

#define arginfo_swoole_timer_clear arginfo_swoole_timer_exists

#define arginfo_swoole_timer_clear_all arginfo_swoole_timer_stats
