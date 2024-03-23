/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 86ee0e408295738c52a0f9944e4ed83b6f4fadf3 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Thread___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_join, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_joinable arginfo_class_Swoole_Thread_join

#define arginfo_class_Swoole_Thread_detach arginfo_class_Swoole_Thread_join

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Thread_exec, 0, 1, Swoole\\Thread, 0)
	ZEND_ARG_TYPE_INFO(0, script_file, IS_STRING, 0)
	ZEND_ARG_VARIADIC_TYPE_INFO(0, args, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getArguments, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getId, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_Map___construct arginfo_class_Swoole_Thread___construct

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Map_offsetGet, 0, 1, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Map_offsetExists, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Map_offsetSet, 0, 2, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Map_offsetUnset, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_MIXED, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_Map_count arginfo_class_Swoole_Thread_getId

#define arginfo_class_Swoole_Thread_Map_keys arginfo_class_Swoole_Thread_getArguments

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_Map_clean, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_Map___wakeup arginfo_class_Swoole_Thread_Map_clean

#define arginfo_class_Swoole_Thread_ArrayList___construct arginfo_class_Swoole_Thread___construct

#define arginfo_class_Swoole_Thread_ArrayList_offsetGet arginfo_class_Swoole_Thread_Map_offsetGet

#define arginfo_class_Swoole_Thread_ArrayList_offsetExists arginfo_class_Swoole_Thread_Map_offsetExists

#define arginfo_class_Swoole_Thread_ArrayList_offsetSet arginfo_class_Swoole_Thread_Map_offsetSet

#define arginfo_class_Swoole_Thread_ArrayList_offsetUnset arginfo_class_Swoole_Thread_Map_offsetUnset

#define arginfo_class_Swoole_Thread_ArrayList_count arginfo_class_Swoole_Thread_getId

#define arginfo_class_Swoole_Thread_ArrayList_clean arginfo_class_Swoole_Thread_Map_clean

#define arginfo_class_Swoole_Thread_ArrayList___wakeup arginfo_class_Swoole_Thread_Map_clean
