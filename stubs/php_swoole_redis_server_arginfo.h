/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 1e207ba7f34bd7ec614d204c150e8c9ac5fcacfb */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Redis_Server_setHandler, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, command, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_Redis_Server_getHandler, 0, 1, Closure, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, command, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Redis_Server_format, 0, 1, MAY_BE_FALSE|MAY_BE_STRING)
	ZEND_ARG_TYPE_INFO(0, type, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, value, IS_MIXED, 0, "null")
ZEND_END_ARG_INFO()
