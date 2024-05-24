/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: e8d4c9f0d13a62fd6a0d67838b26cb4451f89ee9 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Thread_Lock___construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_LONG, 0, "SWOOLE_MUTEX")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Thread_Lock___destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Lock_lock, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Lock_locakwait, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "1.0")
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_Lock_trylock arginfo_class_Swoole_Thread_Lock_lock

#define arginfo_class_Swoole_Thread_Lock_lock_read arginfo_class_Swoole_Thread_Lock_lock

#define arginfo_class_Swoole_Thread_Lock_trylock_read arginfo_class_Swoole_Thread_Lock_lock

#define arginfo_class_Swoole_Thread_Lock_unlock arginfo_class_Swoole_Thread_Lock_lock

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Lock___wakeup, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()
