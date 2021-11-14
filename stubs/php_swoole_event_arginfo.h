/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 1a6145a7e3170f0d085df9004d63d2a430a05f1a */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_add, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, read_callback, IS_CALLABLE, 1)
	ZEND_ARG_TYPE_INFO(0, write_callback, IS_CALLABLE, 1)
	ZEND_ARG_TYPE_INFO(0, events, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_event_set arginfo_swoole_event_add

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_del, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_write, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_wait, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_event_rshutdown arginfo_swoole_event_wait

#define arginfo_swoole_event_exit arginfo_swoole_event_wait

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_defer, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_cycle, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 1)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, before, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_dispatch, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_event_isset, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, events, IS_LONG, 0)
ZEND_END_ARG_INFO()
