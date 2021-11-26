ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_setHandler, 0, 0, 2)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_getHandler, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_format, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Redis_Server_setHandler arginfo_swoole_redis_server_setHandler
#define arginfo_class_Swoole_Redis_Server_getHandler arginfo_swoole_redis_server_getHandler
#define arginfo_class_Swoole_Redis_Server_format     arginfo_swoole_redis_server_format
