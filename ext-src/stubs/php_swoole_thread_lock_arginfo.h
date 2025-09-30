/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 3d97d9a6192d9e86fc94eda474145f2cdbb0760e */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Thread_Lock___construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_LONG, 0, "SWOOLE_MUTEX")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Lock_lock, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, operation, IS_LONG, 0, "LOCK_EX")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "-1")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Lock_unlock, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()
