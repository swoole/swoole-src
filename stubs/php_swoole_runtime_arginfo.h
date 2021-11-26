/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 608f0058d657d34cb5e9b5b9f3a31feaa105b294 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Runtime_enableCoroutine, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_MASK(0, enable, MAY_BE_BOOL|MAY_BE_LONG, "SWOOLE_HOOK_ALL")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "SWOOLE_HOOK_ALL")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Runtime_getHookFlags, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Runtime_setHookFlags, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()
