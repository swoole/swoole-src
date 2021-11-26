ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_runtime_enableCoroutine, 0, 0, 0)
    ZEND_ARG_INFO(0, enable)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_runtime_setHookFlags, 0, 0, 1)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Runtime_enableCoroutine arginfo_swoole_runtime_enableCoroutine
#define arginfo_class_Swoole_Runtime_getHookFlags    arginfo_swoole_void
#define arginfo_class_Swoole_Runtime_setHookFlags    arginfo_swoole_runtime_setHookFlags
