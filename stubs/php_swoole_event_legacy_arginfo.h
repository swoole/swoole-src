ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_add, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_CALLABLE_INFO(0, read_callback, 1)
    ZEND_ARG_CALLABLE_INFO(0, write_callback, 1)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_set, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_CALLABLE_INFO(0, read_callback, 1)
    ZEND_ARG_CALLABLE_INFO(0, write_callback, 1)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_write, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_defer, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_cycle, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 1)
    ZEND_ARG_INFO(0, before)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_del, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_isset, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

#define arginfo_swoole_event_dispatch   arginfo_swoole_void
#define arginfo_swoole_event_wait       arginfo_swoole_void
#define arginfo_swoole_event_rshutdown  arginfo_swoole_void
#define arginfo_swoole_event_exit       arginfo_swoole_void
