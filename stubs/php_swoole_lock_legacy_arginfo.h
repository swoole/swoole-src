ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_lock_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_lock_lockwait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Lock___construct  arginfo_swoole_lock_construct
#define arginfo_class_Swoole_Lock_locakwait    arginfo_swoole_lock_lockwait
#define arginfo_class_Swoole_Lock___destruct   arginfo_swoole_void
#define arginfo_class_Swoole_Lock_lock         arginfo_swoole_void
#define arginfo_class_Swoole_Lock_trylock      arginfo_swoole_void
#define arginfo_class_Swoole_Lock_lock_read    arginfo_swoole_void
#define arginfo_class_Swoole_Lock_trylock_read arginfo_swoole_void
#define arginfo_class_Swoole_Lock_unlock       arginfo_swoole_void
#define arginfo_class_Swoole_Lock_destroy      arginfo_swoole_void
