ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, async)
    ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, sock_flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_close, 0, 0, 0)
    ZEND_ARG_INFO(0, force)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_shutdown, 0, 0, 1)
    ZEND_ARG_INFO(0, how)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Client___construct arginfo_swoole_client_construct
#define arginfo_class_Swoole_Client___destruct arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_set arginfo_swoole_client_set
#define arginfo_class_Swoole_Client_connect arginfo_swoole_client_connect
#define arginfo_class_Swoole_Client_recv arginfo_swoole_client_recv
#define arginfo_class_Swoole_Client_send arginfo_swoole_client_send
#define arginfo_class_Swoole_Client_sendfile arginfo_swoole_client_sendfile
#define arginfo_class_Swoole_Client_sendto arginfo_swoole_client_sendto
#define arginfo_class_Swoole_Client_shutdown arginfo_swoole_client_shutdown

#ifdef SW_USE_OPENSSL
#define arginfo_class_Swoole_Client_enableSSL arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_getPeerCert arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_verifyPeerCert arginfo_swoole_client_void
#endif

#define arginfo_class_Swoole_Client_isConnected arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_getsockname arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_getpeername arginfo_swoole_client_void
#define arginfo_class_Swoole_Client_close arginfo_swoole_client_close

#ifdef SWOOLE_SOCKETS_SUPPORT
#define arginfo_class_Swoole_Client_getSocket arginfo_swoole_client_void
#endif
