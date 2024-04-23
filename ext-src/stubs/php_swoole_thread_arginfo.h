/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 47148b0067d99c44ab50739f4184b021db929a6a */

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
