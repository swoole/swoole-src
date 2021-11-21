ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_add, 0, 0, 0)
    ZEND_ARG_INFO(0, add_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_sub, 0, 0, 0)
    ZEND_ARG_INFO(0, sub_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_get, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_set, 0, 0, 1)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_cmpset, 0, 0, 2)
    ZEND_ARG_INFO(0, cmp_value)
    ZEND_ARG_INFO(0, new_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_atomic_wakeup, 0, 0, 0)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Atomic___construct      arginfo_swoole_atomic_construct
#define arginfo_class_Swoole_Atomic_add              arginfo_swoole_atomic_add
#define arginfo_class_Swoole_Atomic_sub              arginfo_swoole_atomic_sub
#define arginfo_class_Swoole_Atomic_get              arginfo_swoole_atomic_get
#define arginfo_class_Swoole_Atomic_set              arginfo_swoole_atomic_set
#define arginfo_class_Swoole_Atomic_wait             arginfo_swoole_atomic_wait
#define arginfo_class_Swoole_Atomic_wakeup           arginfo_swoole_atomic_wakeup
#define arginfo_class_Swoole_Atomic_cmpset           arginfo_swoole_atomic_cmpset
#define arginfo_class_Swoole_Atomic_Long___construct arginfo_swoole_atomic_construct
#define arginfo_class_Swoole_Atomic_Long_add         arginfo_swoole_atomic_add
#define arginfo_class_Swoole_Atomic_Long_sub         arginfo_swoole_atomic_sub
#define arginfo_class_Swoole_Atomic_Long_get         arginfo_swoole_atomic_get
#define arginfo_class_Swoole_Atomic_Long_set         arginfo_swoole_atomic_set
#define arginfo_class_Swoole_Atomic_Long_cmpset      arginfo_swoole_atomic_cmpset
