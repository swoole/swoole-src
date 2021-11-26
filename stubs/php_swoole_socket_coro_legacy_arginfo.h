ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_construct, 0, 0, 2)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, protocol)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_bind, 0, 0, 1)
    ZEND_ARG_INFO(0, address)
    ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_listen, 0, 0, 0)
    ZEND_ARG_INFO(0, backlog)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_accept, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_checkLiveness, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_peek, 0, 0, 0)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_recvPacket, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_readVector, 0, 0, 1)
    ZEND_ARG_INFO(0, io_vector)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_readVectorAll, 0, 0, 1)
    ZEND_ARG_INFO(0, io_vector)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_writeVector, 0, 0, 1)
    ZEND_ARG_INFO(0, io_vector)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_writeVectorAll, 0, 0, 1)
    ZEND_ARG_INFO(0, io_vector)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_sendFile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_recvfrom, 0, 0, 1)
    ZEND_ARG_INFO(1, peername)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_getOption, 0, 0, 2)
    ZEND_ARG_INFO(0, level)
    ZEND_ARG_INFO(0, opt_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_setOption, 0, 0, 3)
    ZEND_ARG_INFO(0, level)
    ZEND_ARG_INFO(0, opt_name)
    ZEND_ARG_INFO(0, opt_value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_setProtocol, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, addr)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_cancel, 0, 0, 0)
    ZEND_ARG_INFO(0, event)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_shutdown, 0, 0, 0)
    ZEND_ARG_INFO(0, how)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Socket___construct       arginfo_swoole_socket_coro_construct
#define arginfo_class_Swoole_Coroutine_Socket_bind              arginfo_swoole_socket_coro_bind
#define arginfo_class_Swoole_Coroutine_Socket_listen            arginfo_swoole_socket_coro_listen
#define arginfo_class_Swoole_Coroutine_Socket_accept            arginfo_swoole_socket_coro_accept
#define arginfo_class_Swoole_Coroutine_Socket_connect           arginfo_swoole_socket_coro_connect
#define arginfo_class_Swoole_Coroutine_Socket_checkLiveness     arginfo_swoole_socket_coro_checkLiveness
#define arginfo_class_Swoole_Coroutine_Socket_peek              arginfo_swoole_socket_coro_peek
#define arginfo_class_Swoole_Coroutine_Socket_recv              arginfo_swoole_socket_coro_recv
#define arginfo_class_Swoole_Coroutine_Socket_recvAll           arginfo_swoole_socket_coro_recv
#define arginfo_class_Swoole_Coroutine_Socket_recvLine          arginfo_swoole_socket_coro_recv
#define arginfo_class_Swoole_Coroutine_Socket_recvWithBuffer    arginfo_swoole_socket_coro_recv
#define arginfo_class_Swoole_Coroutine_Socket_recvPacket        arginfo_swoole_socket_coro_recvPacket
#define arginfo_class_Swoole_Coroutine_Socket_send              arginfo_swoole_socket_coro_send
#define arginfo_class_Swoole_Coroutine_Socket_readVector        arginfo_swoole_socket_coro_readVector
#define arginfo_class_Swoole_Coroutine_Socket_readVectorAll     arginfo_swoole_socket_coro_readVectorAll
#define arginfo_class_Swoole_Coroutine_Socket_writeVector       arginfo_swoole_socket_coro_writeVector
#define arginfo_class_Swoole_Coroutine_Socket_writeVectorAll    arginfo_swoole_socket_coro_writeVectorAll
#define arginfo_class_Swoole_Coroutine_Socket_sendFile          arginfo_swoole_socket_coro_sendFile
#define arginfo_class_Swoole_Coroutine_Socket_sendAll           arginfo_swoole_socket_coro_send
#define arginfo_class_Swoole_Coroutine_Socket_recvfrom          arginfo_swoole_socket_coro_recvfrom
#define arginfo_class_Swoole_Coroutine_Socket_sendto            arginfo_swoole_socket_coro_sendto
#define arginfo_class_Swoole_Coroutine_Socket_getOption         arginfo_swoole_socket_coro_getOption
#define arginfo_class_Swoole_Coroutine_Socket_setProtocol       arginfo_swoole_socket_coro_setProtocol
#define arginfo_class_Swoole_Coroutine_Socket_setOption         arginfo_swoole_socket_coro_setOption
#define arginfo_class_Swoole_Coroutine_Socket_sslHandshake      arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Socket_shutdown          arginfo_swoole_socket_coro_shutdown
#define arginfo_class_Swoole_Coroutine_Socket_cancel            arginfo_swoole_socket_coro_cancel
#define arginfo_class_Swoole_Coroutine_Socket_close             arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Socket_getpeername       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Socket_getsockname       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Socket_isClosed          arginfo_swoole_void
