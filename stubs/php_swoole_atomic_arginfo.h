/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 7c83f8fbe7fd48ac2c7a2756a4e33a9edd666e42 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Atomic___construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, value, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_add, 0, 0, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, add_value, IS_LONG, 0, "1")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_sub, 0, 0, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sub_value, IS_LONG, 0, "1")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_get, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_set, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_cmpset, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, cmp_value, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, new_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_wait, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "1.0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Atomic_wakeup, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, count, IS_LONG, 0, "1")
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Atomic_Long___construct arginfo_class_Swoole_Atomic___construct

#define arginfo_class_Swoole_Atomic_Long_add arginfo_class_Swoole_Atomic_add

#define arginfo_class_Swoole_Atomic_Long_sub arginfo_class_Swoole_Atomic_sub

#define arginfo_class_Swoole_Atomic_Long_get arginfo_class_Swoole_Atomic_get

#define arginfo_class_Swoole_Atomic_Long_set arginfo_class_Swoole_Atomic_set

#define arginfo_class_Swoole_Atomic_Long_cmpset arginfo_class_Swoole_Atomic_cmpset
