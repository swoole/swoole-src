ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
    ZEND_ARG_INFO(0, reuse_port)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_handle, 0, 0, 2)
    ZEND_ARG_INFO(0, pattern)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_server_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Http_Server___construct arginfo_swoole_http_server_coro_construct
#define arginfo_class_Swoole_Coroutine_Http_Server___destruct  arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Server_handle      arginfo_swoole_http_server_coro_handle
#define arginfo_class_Swoole_Coroutine_Http_Server_set         arginfo_swoole_http_server_coro_set
#define arginfo_class_Swoole_Coroutine_Http_Server_onAccept    arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Server_start       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Server_shutdown    arginfo_swoole_void
