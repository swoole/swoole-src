ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, sock_flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_peek, 0, 0, 0)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, address)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_recvfrom, 0, 0, 2)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(1, address)
    ZEND_ARG_INFO(1, port)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Client___construct    arginfo_swoole_client_coro_construct
#define arginfo_class_Swoole_Coroutine_Client___destruct     arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_set            arginfo_swoole_client_coro_set
#define arginfo_class_Swoole_Coroutine_Client_connect        arginfo_swoole_client_coro_connect
#define arginfo_class_Swoole_Coroutine_Client_recv           arginfo_swoole_client_coro_recv
#define arginfo_class_Swoole_Coroutine_Client_peek           arginfo_swoole_client_coro_peek
#define arginfo_class_Swoole_Coroutine_Client_send           arginfo_swoole_client_coro_send
#define arginfo_class_Swoole_Coroutine_Client_sendfile       arginfo_swoole_client_coro_sendfile
#define arginfo_class_Swoole_Coroutine_Client_sendto         arginfo_swoole_client_coro_sendto
#define arginfo_class_Swoole_Coroutine_Client_recvfrom       arginfo_swoole_client_coro_recvfrom
#define arginfo_class_Swoole_Coroutine_Client_enableSSL      arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_getPeerCert    arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_verifyPeerCert arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_isConnected    arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_getsockname    arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_getpeername    arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_close          arginfo_swoole_client_coro_void
#define arginfo_class_Swoole_Coroutine_Client_exportSocket   arginfo_swoole_client_coro_void