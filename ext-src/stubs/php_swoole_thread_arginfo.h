/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: d1d1e5d35cfda110527408faf9376dda24680c7f */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Thread___construct, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, script_file, IS_STRING, 0)
	ZEND_ARG_VARIADIC_TYPE_INFO(0, args, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_join, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_joinable arginfo_class_Swoole_Thread_join

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getExitStatus, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_detach arginfo_class_Swoole_Thread_join

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getArguments, 0, 0, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_getId arginfo_class_Swoole_Thread_getExitStatus

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getInfo, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_setName, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

#if defined(HAVE_CPU_AFFINITY)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_setAffinity, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, cpu_settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()
#endif

#if defined(HAVE_CPU_AFFINITY)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_getAffinity, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Thread_setPriority, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, priority, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, policy, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Thread_getPriority arginfo_class_Swoole_Thread_getInfo

#define arginfo_class_Swoole_Thread_getNativeId arginfo_class_Swoole_Thread_getExitStatus
