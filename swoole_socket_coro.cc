/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"

#include "thirdparty/sockets/php_sockets_cxx.h"

#include <string>

using namespace swoole;

zend_class_entry *swoole_socket_coro_ce;
static zend_object_handlers swoole_socket_coro_handlers;

static zend_class_entry *swoole_socket_coro_exception_ce;
static zend_object_handlers swoole_socket_coro_exception_handlers;

typedef struct
{
    Socket *socket;
#ifdef SWOOLE_SOCKETS_SUPPORT
    zval *resource;
#endif
    zend_object std;
} socket_coro;

static PHP_METHOD(swoole_socket_coro, __construct);
static PHP_METHOD(swoole_socket_coro, bind);
static PHP_METHOD(swoole_socket_coro, listen);
static PHP_METHOD(swoole_socket_coro, accept);
static PHP_METHOD(swoole_socket_coro, connect);
static PHP_METHOD(swoole_socket_coro, recv);
static PHP_METHOD(swoole_socket_coro, send);
static PHP_METHOD(swoole_socket_coro, recvAll);
static PHP_METHOD(swoole_socket_coro, sendAll);
static PHP_METHOD(swoole_socket_coro, recvfrom);
static PHP_METHOD(swoole_socket_coro, sendto);
static PHP_METHOD(swoole_socket_coro, getOption);
static PHP_METHOD(swoole_socket_coro, setOption);
static PHP_METHOD(swoole_socket_coro, shutdown);
static PHP_METHOD(swoole_socket_coro, close);
static PHP_METHOD(swoole_socket_coro, getsockname);
static PHP_METHOD(swoole_socket_coro, getpeername);
#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_socket_coro, getSocket);
#endif

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, timeout)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, addr)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_shutdown, 0, 0, 1)
    ZEND_ARG_INFO(0, how)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_socket_coro_methods[] =
{
    PHP_ME(swoole_socket_coro, __construct, arginfo_swoole_socket_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, bind,        arginfo_swoole_socket_coro_bind,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, listen,      arginfo_swoole_socket_coro_listen,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, accept,      arginfo_swoole_socket_coro_accept,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, connect,     arginfo_swoole_socket_coro_connect,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, recv,        arginfo_swoole_socket_coro_recv,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, send,        arginfo_swoole_socket_coro_send,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, recvAll,     arginfo_swoole_socket_coro_recv,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, sendAll,     arginfo_swoole_socket_coro_send,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, recvfrom,    arginfo_swoole_socket_coro_recvfrom,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, sendto,      arginfo_swoole_socket_coro_sendto,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getOption,   arginfo_swoole_socket_coro_getOption, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, setOption,   arginfo_swoole_socket_coro_setOption, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, shutdown,    arginfo_swoole_socket_coro_shutdown,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, close,       arginfo_swoole_void,                  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getpeername, arginfo_swoole_void,                  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getsockname, arginfo_swoole_void,                  ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_socket_coro, getSocket,   arginfo_swoole_void,                  ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

#define SW_BAD_SOCKET ((Socket *)-1)
#define swoole_get_socket_coro(_sock, _zobject) \
        socket_coro* _sock = swoole_socket_coro_fetch_object(Z_OBJ_P(_zobject)); \
        if (UNEXPECTED(!sock->socket)) \
        { \
            swoole_php_fatal_error(E_ERROR, "you must call Socket constructor first"); \
        } \
        if (UNEXPECTED(_sock->socket == SW_BAD_SOCKET)) { \
            zend_update_property_long(swoole_socket_coro_ce, _zobject, ZEND_STRL("errCode"), EBADF); \
            zend_update_property_string(swoole_socket_coro_ce, _zobject, ZEND_STRL("errMsg"), strerror(EBADF)); \
            RETURN_FALSE; \
        }

static sw_inline socket_coro* swoole_socket_coro_fetch_object(zend_object *obj)
{
    return (socket_coro *) ((char *) obj - swoole_socket_coro_handlers.offset);
}

static void swoole_socket_coro_free_object(zend_object *object)
{
    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(object);
#ifdef SWOOLE_SOCKETS_SUPPORT
    if (sock->resource)
    {
        swoole_php_socket_free(sock->resource);
        sock->resource = nullptr;
    }
#endif
    if (sock->socket && sock->socket != SW_BAD_SOCKET)
    {
        assert(!sock->socket->has_bound());
        sock->socket->close();
        delete sock->socket;
    }
    zend_object_std_dtor(&sock->std);
}

static zend_object* swoole_socket_coro_create_object(zend_class_entry *ce)
{
    socket_coro *sock = (socket_coro *) ecalloc(1, sizeof(socket_coro) + zend_object_properties_size(ce));
    zend_object_std_init(&sock->std, ce);
    /* Even if you don't use properties yourself you should still call object_properties_init(),
     * because extending classes may use properties. (Generally a lot of the stuff you will do is
     * for the sake of not breaking extending classes). */
    object_properties_init(&sock->std, ce);
    sock->std.handlers = &swoole_socket_coro_handlers;
    return &sock->std;
}

static void swoole_socket_coro_register_constants(int module_number)
{
    REGISTER_LONG_CONSTANT("AF_UNIX", AF_UNIX, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AF_INET", AF_INET, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AF_INET6", AF_INET6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOCK_STREAM", SOCK_STREAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOCK_DGRAM", SOCK_DGRAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOCK_RAW", SOCK_RAW, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOCK_SEQPACKET", SOCK_SEQPACKET, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOCK_RDM", SOCK_RDM, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("MSG_OOB", MSG_OOB, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MSG_WAITALL", MSG_WAITALL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MSG_CTRUNC", MSG_CTRUNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MSG_TRUNC", MSG_TRUNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MSG_PEEK", MSG_PEEK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MSG_DONTROUTE", MSG_DONTROUTE, CONST_CS | CONST_PERSISTENT);
#ifdef MSG_EOR
    REGISTER_LONG_CONSTANT("MSG_EOR", MSG_EOR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_EOF
    REGISTER_LONG_CONSTANT("MSG_EOF", MSG_EOF, CONST_CS | CONST_PERSISTENT);
#endif

#ifdef MSG_CONFIRM
    REGISTER_LONG_CONSTANT("MSG_CONFIRM", MSG_CONFIRM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_ERRQUEUE
    REGISTER_LONG_CONSTANT("MSG_ERRQUEUE", MSG_ERRQUEUE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_NOSIGNAL
    REGISTER_LONG_CONSTANT("MSG_NOSIGNAL", MSG_NOSIGNAL, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_DONTWAIT
    REGISTER_LONG_CONSTANT("MSG_DONTWAIT", MSG_DONTWAIT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_MORE
    REGISTER_LONG_CONSTANT("MSG_MORE", MSG_MORE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_WAITFORONE
    REGISTER_LONG_CONSTANT("MSG_WAITFORONE",MSG_WAITFORONE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef MSG_CMSG_CLOEXEC
    REGISTER_LONG_CONSTANT("MSG_CMSG_CLOEXEC",MSG_CMSG_CLOEXEC,CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("SO_DEBUG", SO_DEBUG, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_REUSEADDR", SO_REUSEADDR, CONST_CS | CONST_PERSISTENT);
#ifdef SO_REUSEPORT
    REGISTER_LONG_CONSTANT("SO_REUSEPORT", SO_REUSEPORT, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SO_KEEPALIVE", SO_KEEPALIVE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_DONTROUTE", SO_DONTROUTE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_LINGER", SO_LINGER, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_BROADCAST", SO_BROADCAST, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_OOBINLINE", SO_OOBINLINE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_SNDBUF", SO_SNDBUF, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_RCVBUF", SO_RCVBUF, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_SNDLOWAT", SO_SNDLOWAT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_RCVLOWAT", SO_RCVLOWAT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_SNDTIMEO", SO_SNDTIMEO, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_RCVTIMEO", SO_RCVTIMEO, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_TYPE", SO_TYPE, CONST_CS | CONST_PERSISTENT);
#ifdef SO_FAMILY
    REGISTER_LONG_CONSTANT("SO_FAMILY", SO_FAMILY, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SO_ERROR", SO_ERROR, CONST_CS | CONST_PERSISTENT);
#ifdef SO_BINDTODEVICE
    REGISTER_LONG_CONSTANT("SO_BINDTODEVICE", SO_BINDTODEVICE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef SO_USER_COOKIE
    REGISTER_LONG_CONSTANT("SO_LABEL", SO_LABEL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_PEERLABEL", SO_PEERLABEL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_LISTENQLIMIT", SO_LISTENQLIMIT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_LISTENQLEN", SO_LISTENQLEN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SO_USER_COOKIE", SO_USER_COOKIE, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SOL_SOCKET", SOL_SOCKET, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOMAXCONN", SOMAXCONN, CONST_CS | CONST_PERSISTENT);
#ifdef TCP_NODELAY
    REGISTER_LONG_CONSTANT("TCP_NODELAY", TCP_NODELAY, CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("MCAST_JOIN_GROUP", PHP_MCAST_JOIN_GROUP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MCAST_LEAVE_GROUP", PHP_MCAST_LEAVE_GROUP, CONST_CS | CONST_PERSISTENT);
#ifdef HAS_MCAST_EXT
    REGISTER_LONG_CONSTANT("MCAST_BLOCK_SOURCE", PHP_MCAST_BLOCK_SOURCE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MCAST_UNBLOCK_SOURCE", PHP_MCAST_UNBLOCK_SOURCE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MCAST_JOIN_SOURCE_GROUP", PHP_MCAST_JOIN_SOURCE_GROUP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("MCAST_LEAVE_SOURCE_GROUP", PHP_MCAST_LEAVE_SOURCE_GROUP, CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("IP_MULTICAST_IF", IP_MULTICAST_IF, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IP_MULTICAST_TTL", IP_MULTICAST_TTL, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IP_MULTICAST_LOOP", IP_MULTICAST_LOOP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IPV6_MULTICAST_IF", IPV6_MULTICAST_IF, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IPV6_MULTICAST_HOPS", IPV6_MULTICAST_HOPS, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IPV6_MULTICAST_LOOP", IPV6_MULTICAST_LOOP, CONST_CS | CONST_PERSISTENT);

#ifdef IPV6_V6ONLY
    REGISTER_LONG_CONSTANT("IPV6_V6ONLY", IPV6_V6ONLY, CONST_CS | CONST_PERSISTENT);
#endif

#ifdef EPERM
    /* Operation not permitted */
    REGISTER_LONG_CONSTANT("SOCKET_EPERM", EPERM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOENT
    /* No such file or directory */
    REGISTER_LONG_CONSTANT("SOCKET_ENOENT", ENOENT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EINTR
    /* Interrupted system call */
    REGISTER_LONG_CONSTANT("SOCKET_EINTR", EINTR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EIO
    /* I/O error */
    REGISTER_LONG_CONSTANT("SOCKET_EIO", EIO, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENXIO
    /* No such device or address */
    REGISTER_LONG_CONSTANT("SOCKET_ENXIO", ENXIO, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef E2BIG
    /* Arg list too long */
    REGISTER_LONG_CONSTANT("SOCKET_E2BIG", E2BIG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADF
    /* Bad file number */
    REGISTER_LONG_CONSTANT("SOCKET_EBADF", EBADF, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EAGAIN
    /* Try again */
    REGISTER_LONG_CONSTANT("SOCKET_EAGAIN", EAGAIN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOMEM
    /* Out of memory */
    REGISTER_LONG_CONSTANT("SOCKET_ENOMEM", ENOMEM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EACCES
    /* Permission denied */
    REGISTER_LONG_CONSTANT("SOCKET_EACCES", EACCES, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EFAULT
    /* Bad address */
    REGISTER_LONG_CONSTANT("SOCKET_EFAULT", EFAULT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTBLK
    /* Block device required */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTBLK", ENOTBLK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBUSY
    /* Device or resource busy */
    REGISTER_LONG_CONSTANT("SOCKET_EBUSY", EBUSY, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EEXIST
    /* File exists */
    REGISTER_LONG_CONSTANT("SOCKET_EEXIST", EEXIST, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EXDEV
    /* Cross-device link */
    REGISTER_LONG_CONSTANT("SOCKET_EXDEV", EXDEV, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENODEV
    /* No such device */
    REGISTER_LONG_CONSTANT("SOCKET_ENODEV", ENODEV, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTDIR
    /* Not a directory */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTDIR", ENOTDIR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EISDIR
    /* Is a directory */
    REGISTER_LONG_CONSTANT("SOCKET_EISDIR", EISDIR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EINVAL
    /* Invalid argument */
    REGISTER_LONG_CONSTANT("SOCKET_EINVAL", EINVAL, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENFILE
    /* File table overflow */
    REGISTER_LONG_CONSTANT("SOCKET_ENFILE", ENFILE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EMFILE
    /* Too many open files */
    REGISTER_LONG_CONSTANT("SOCKET_EMFILE", EMFILE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTTY
    /* Not a typewriter */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTTY", ENOTTY, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOSPC
    /* No space left on device */
    REGISTER_LONG_CONSTANT("SOCKET_ENOSPC", ENOSPC, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ESPIPE
    /* Illegal seek */
    REGISTER_LONG_CONSTANT("SOCKET_ESPIPE", ESPIPE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EROFS
    /* Read-only file system */
    REGISTER_LONG_CONSTANT("SOCKET_EROFS", EROFS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EMLINK
    /* Too many links */
    REGISTER_LONG_CONSTANT("SOCKET_EMLINK", EMLINK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EPIPE
    /* Broken pipe */
    REGISTER_LONG_CONSTANT("SOCKET_EPIPE", EPIPE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENAMETOOLONG
    /* File name too long */
    REGISTER_LONG_CONSTANT("SOCKET_ENAMETOOLONG", ENAMETOOLONG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOLCK
    /* No record locks available */
    REGISTER_LONG_CONSTANT("SOCKET_ENOLCK", ENOLCK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOSYS
    /* Function not implemented */
    REGISTER_LONG_CONSTANT("SOCKET_ENOSYS", ENOSYS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTEMPTY
    /* Directory not empty */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTEMPTY", ENOTEMPTY, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ELOOP
    /* Too many symbolic links encountered */
    REGISTER_LONG_CONSTANT("SOCKET_ELOOP", ELOOP, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EWOULDBLOCK
    /* Operation would block */
    REGISTER_LONG_CONSTANT("SOCKET_EWOULDBLOCK", EWOULDBLOCK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOMSG
    /* No message of desired type */
    REGISTER_LONG_CONSTANT("SOCKET_ENOMSG", ENOMSG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EIDRM
    /* Identifier removed */
    REGISTER_LONG_CONSTANT("SOCKET_EIDRM", EIDRM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ECHRNG
    /* Channel number out of range */
    REGISTER_LONG_CONSTANT("SOCKET_ECHRNG", ECHRNG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EL2NSYNC
    /* Level 2 not synchronized */
    REGISTER_LONG_CONSTANT("SOCKET_EL2NSYNC", EL2NSYNC, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EL3HLT
    /* Level 3 halted */
    REGISTER_LONG_CONSTANT("SOCKET_EL3HLT", EL3HLT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EL3RST
    /* Level 3 reset */
    REGISTER_LONG_CONSTANT("SOCKET_EL3RST", EL3RST, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ELNRNG
    /* Link number out of range */
    REGISTER_LONG_CONSTANT("SOCKET_ELNRNG", ELNRNG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EUNATCH
    /* Protocol driver not attached */
    REGISTER_LONG_CONSTANT("SOCKET_EUNATCH", EUNATCH, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOCSI
    /* No CSI structure available */
    REGISTER_LONG_CONSTANT("SOCKET_ENOCSI", ENOCSI, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EL2HLT
    /* Level 2 halted */
    REGISTER_LONG_CONSTANT("SOCKET_EL2HLT", EL2HLT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADE
    /* Invalid exchange */
    REGISTER_LONG_CONSTANT("SOCKET_EBADE", EBADE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADR
    /* Invalid request descriptor */
    REGISTER_LONG_CONSTANT("SOCKET_EBADR", EBADR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EXFULL
    /* Exchange full */
    REGISTER_LONG_CONSTANT("SOCKET_EXFULL", EXFULL, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOANO
    /* No anode */
    REGISTER_LONG_CONSTANT("SOCKET_ENOANO", ENOANO, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADRQC
    /* Invalid request code */
    REGISTER_LONG_CONSTANT("SOCKET_EBADRQC", EBADRQC, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADSLT
    /* Invalid slot */
    REGISTER_LONG_CONSTANT("SOCKET_EBADSLT", EBADSLT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOSTR
    /* Device not a stream */
    REGISTER_LONG_CONSTANT("SOCKET_ENOSTR", ENOSTR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENODATA
    /* No data available */
    REGISTER_LONG_CONSTANT("SOCKET_ENODATA", ENODATA, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ETIME
    /* Timer expired */
    REGISTER_LONG_CONSTANT("SOCKET_ETIME", ETIME, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOSR
    /* Out of streams resources */
    REGISTER_LONG_CONSTANT("SOCKET_ENOSR", ENOSR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENONET
    /* Machine is not on the network */
    REGISTER_LONG_CONSTANT("SOCKET_ENONET", ENONET, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EREMOTE
    /* Object is remote */
    REGISTER_LONG_CONSTANT("SOCKET_EREMOTE", EREMOTE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOLINK
    /* Link has been severed */
    REGISTER_LONG_CONSTANT("SOCKET_ENOLINK", ENOLINK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EADV
    /* Advertise error */
    REGISTER_LONG_CONSTANT("SOCKET_EADV", EADV, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ESRMNT
    /* Srmount error */
    REGISTER_LONG_CONSTANT("SOCKET_ESRMNT", ESRMNT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ECOMM
    /* Communication error on send */
    REGISTER_LONG_CONSTANT("SOCKET_ECOMM", ECOMM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EPROTO
    /* Protocol error */
    REGISTER_LONG_CONSTANT("SOCKET_EPROTO", EPROTO, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EMULTIHOP
    /* Multihop attempted */
    REGISTER_LONG_CONSTANT("SOCKET_EMULTIHOP", EMULTIHOP, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADMSG
    /* Not a data message */
    REGISTER_LONG_CONSTANT("SOCKET_EBADMSG", EBADMSG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTUNIQ
    /* Name not unique on network */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTUNIQ", ENOTUNIQ, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EBADFD
    /* File descriptor in bad state */
    REGISTER_LONG_CONSTANT("SOCKET_EBADFD", EBADFD, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EREMCHG
    /* Remote address changed */
    REGISTER_LONG_CONSTANT("SOCKET_EREMCHG", EREMCHG, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ERESTART
    /* Interrupted system call should be restarted */
    REGISTER_LONG_CONSTANT("SOCKET_ERESTART", ERESTART, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ESTRPIPE
    /* Streams pipe error */
    REGISTER_LONG_CONSTANT("SOCKET_ESTRPIPE", ESTRPIPE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EUSERS
    /* Too many users */
    REGISTER_LONG_CONSTANT("SOCKET_EUSERS", EUSERS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTSOCK
    /* Socket operation on non-socket */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTSOCK", ENOTSOCK, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EDESTADDRREQ
    /* Destination address required */
    REGISTER_LONG_CONSTANT("SOCKET_EDESTADDRREQ", EDESTADDRREQ, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EMSGSIZE
    /* Message too long */
    REGISTER_LONG_CONSTANT("SOCKET_EMSGSIZE", EMSGSIZE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EPROTOTYPE
    /* Protocol wrong type for socket */
    REGISTER_LONG_CONSTANT("SOCKET_EPROTOTYPE", EPROTOTYPE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOPROTOOPT
    /* Protocol not available */
    REGISTER_LONG_CONSTANT("SOCKET_ENOPROTOOPT", ENOPROTOOPT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EPROTONOSUPPORT
    /* Protocol not supported */
    REGISTER_LONG_CONSTANT("SOCKET_EPROTONOSUPPORT", EPROTONOSUPPORT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ESOCKTNOSUPPORT
    /* Socket type not supported */
    REGISTER_LONG_CONSTANT("SOCKET_ESOCKTNOSUPPORT", ESOCKTNOSUPPORT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EOPNOTSUPP
    /* Operation not supported on transport endpoint */
    REGISTER_LONG_CONSTANT("SOCKET_EOPNOTSUPP", EOPNOTSUPP, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EPFNOSUPPORT
    /* Protocol family not supported */
    REGISTER_LONG_CONSTANT("SOCKET_EPFNOSUPPORT", EPFNOSUPPORT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EAFNOSUPPORT
    /* Address family not supported by protocol */
    REGISTER_LONG_CONSTANT("SOCKET_EAFNOSUPPORT", EAFNOSUPPORT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EADDRINUSE
    /* Address already in use */
    REGISTER_LONG_CONSTANT("SOCKET_EADDRINUSE", EADDRINUSE, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EADDRNOTAVAIL
    /* Cannot assign requested address */
    REGISTER_LONG_CONSTANT("SOCKET_EADDRNOTAVAIL", EADDRNOTAVAIL, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENETDOWN
    /* Network is down */
    REGISTER_LONG_CONSTANT("SOCKET_ENETDOWN", ENETDOWN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENETUNREACH
    /* Network is unreachable */
    REGISTER_LONG_CONSTANT("SOCKET_ENETUNREACH", ENETUNREACH, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENETRESET
    /* Network dropped connection because of reset */
    REGISTER_LONG_CONSTANT("SOCKET_ENETRESET", ENETRESET, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ECONNABORTED
    /* Software caused connection abort */
    REGISTER_LONG_CONSTANT("SOCKET_ECONNABORTED", ECONNABORTED, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ECONNRESET
    /* Connection reset by peer */
    REGISTER_LONG_CONSTANT("SOCKET_ECONNRESET", ECONNRESET, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOBUFS
    /* No buffer space available */
    REGISTER_LONG_CONSTANT("SOCKET_ENOBUFS", ENOBUFS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EISCONN
    /* Transport endpoint is already connected */
    REGISTER_LONG_CONSTANT("SOCKET_EISCONN", EISCONN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOTCONN
    /* Transport endpoint is not connected */
    REGISTER_LONG_CONSTANT("SOCKET_ENOTCONN", ENOTCONN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ESHUTDOWN
    /* Cannot send after transport endpoint shutdown */
    REGISTER_LONG_CONSTANT("SOCKET_ESHUTDOWN", ESHUTDOWN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ETOOMANYREFS
    /* Too many references: cannot splice */
    REGISTER_LONG_CONSTANT("SOCKET_ETOOMANYREFS", ETOOMANYREFS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ETIMEDOUT
    /* Connection timed out */
    REGISTER_LONG_CONSTANT("SOCKET_ETIMEDOUT", ETIMEDOUT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ECONNREFUSED
    /* Connection refused */
    REGISTER_LONG_CONSTANT("SOCKET_ECONNREFUSED", ECONNREFUSED, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EHOSTDOWN
    /* Host is down */
    REGISTER_LONG_CONSTANT("SOCKET_EHOSTDOWN", EHOSTDOWN, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EHOSTUNREACH
    /* No route to host */
    REGISTER_LONG_CONSTANT("SOCKET_EHOSTUNREACH", EHOSTUNREACH, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EALREADY
    /* Operation already in progress */
    REGISTER_LONG_CONSTANT("SOCKET_EALREADY", EALREADY, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EINPROGRESS
    /* Operation now in progress */
    REGISTER_LONG_CONSTANT("SOCKET_EINPROGRESS", EINPROGRESS, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EISNAM
    /* Is a named type file */
    REGISTER_LONG_CONSTANT("SOCKET_EISNAM", EISNAM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EREMOTEIO
    /* Remote I/O error */
    REGISTER_LONG_CONSTANT("SOCKET_EREMOTEIO", EREMOTEIO, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EDQUOT
    /* Quota exceeded */
    REGISTER_LONG_CONSTANT("SOCKET_EDQUOT", EDQUOT, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef ENOMEDIUM
    /* No medium found */
    REGISTER_LONG_CONSTANT("SOCKET_ENOMEDIUM", ENOMEDIUM, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef EMEDIUMTYPE
    /* Wrong medium type */
    REGISTER_LONG_CONSTANT("SOCKET_EMEDIUMTYPE", EMEDIUMTYPE, CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("IPPROTO_IP", IPPROTO_IP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("IPPROTO_IPV6", IPPROTO_IPV6, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("SOL_TCP", IPPROTO_TCP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SOL_UDP", IPPROTO_UDP, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("IPV6_UNICAST_HOPS", IPV6_UNICAST_HOPS, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("AI_PASSIVE", AI_PASSIVE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AI_CANONNAME", AI_CANONNAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AI_NUMERICHOST", AI_NUMERICHOST, CONST_CS | CONST_PERSISTENT);
#if HAVE_AI_V4MAPPED
    REGISTER_LONG_CONSTANT("AI_V4MAPPED", AI_V4MAPPED, CONST_CS | CONST_PERSISTENT);
#endif
#if HAVE_AI_ALL
    REGISTER_LONG_CONSTANT("AI_ALL", AI_ALL, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("AI_ADDRCONFIG", AI_ADDRCONFIG, CONST_CS | CONST_PERSISTENT);
#if HAVE_AI_IDN
    REGISTER_LONG_CONSTANT("AI_IDN", AI_IDN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AI_CANONIDN", AI_CANONIDN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AI_IDN_ALLOW_UNASSIGNED", AI_IDN_ALLOW_UNASSIGNED, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("AI_IDN_USE_STD3_ASCII_RULES", AI_IDN_USE_STD3_ASCII_RULES, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef AI_NUMERICSERV
    REGISTER_LONG_CONSTANT("AI_NUMERICSERV", AI_NUMERICSERV, CONST_CS | CONST_PERSISTENT);
#endif
}

void swoole_socket_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_socket_coro, "Swoole\\Coroutine\\Socket", NULL, "Co\\Socket", swoole_socket_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_socket_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_socket_coro, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_socket_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_socket_coro, swoole_socket_coro_create_object, swoole_socket_coro_free_object, socket_coro, std);

    zend_declare_property_long(swoole_socket_coro_ce, ZEND_STRL("fd"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_socket_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_socket_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY_EX(swoole_socket_coro_exception, "Swoole\\Coroutine\\Socket\\Exception", NULL, "Co\\Socket\\Exception", NULL, swoole_exception);

    if (!zend_hash_str_find_ptr(&module_registry, ZEND_STRL("sockets")))
    {
        swoole_socket_coro_register_constants(module_number);
    }
}

static sw_inline void swoole_socket_coro_sync_properties(zval *zobject, socket_coro *sock)
{
    zend_update_property_long(swoole_socket_coro_ce, zobject, ZEND_STRL("errCode"), sock->socket->errCode);
    zend_update_property_string(swoole_socket_coro_ce, zobject, ZEND_STRL("errMsg"), sock->socket->errMsg);
}

static void sw_inline php_swoole_init_socket(zval *zobject, socket_coro *sock)
{
    zend_update_property_long(swoole_socket_coro_ce, zobject, ZEND_STRL("fd"), sock->socket->get_fd());
}

SW_API bool php_swoole_export_socket(zval *zobject, int fd, enum swSocket_type type)
{
    zend_object *object = swoole_socket_coro_create_object(swoole_socket_coro_ce);
    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(object);

    php_swoole_check_reactor();
    int new_fd = dup(fd);
    if (new_fd < 0)
    {
        swoole_php_sys_error(E_WARNING, "dup(%d) failed", fd);
        return false;
    }
    sock->socket = new Socket(new_fd, type);
    if (UNEXPECTED(sock->socket->socket == nullptr))
    {
        swoole_php_sys_error(E_WARNING, "new Socket() failed");
        delete sock->socket;
        sock->socket = nullptr;
        OBJ_RELEASE(object);
        ZVAL_NULL(zobject);
        return false;
    }
    ZVAL_OBJ(zobject, object);
    php_swoole_init_socket(zobject, sock);
    return true;
}

SW_API zend_object* php_swoole_export_socket_ex(int fd, enum swSocket_type type)
{
    zval zobject;
    return php_swoole_export_socket(&zobject, fd, type) ? Z_OBJ_P(&zobject) : nullptr;
}

SW_API Socket* php_swoole_get_socket(zval *zobject)
{
    SW_ASSERT(Z_OBJCE_P(zobject) == swoole_socket_coro_ce);
    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(Z_OBJ_P(zobject));
    return sock->socket;
}

SW_API void php_swoole_init_socket_object(zval *zobject, Socket *socket)
{
    zend_object *object = swoole_socket_coro_create_object(swoole_socket_coro_ce);
    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(object);
    sock->socket = socket;
    ZVAL_OBJ(zobject, object);
    php_swoole_init_socket(zobject, sock);
}

static PHP_METHOD(swoole_socket_coro, __construct)
{
    zend_long domain, type, protocol = IPPROTO_IP;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 3)
        Z_PARAM_LONG(domain)
        Z_PARAM_LONG(type)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(protocol)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(Z_OBJ_P(getThis()));

    if (EXPECTED(!sock->socket))
    {
        php_swoole_check_reactor();
        sock->socket = new Socket((int)domain, (int)type, (int)protocol);
        if (UNEXPECTED(sock->socket->socket == nullptr))
        {
            zend_throw_exception_ex(
                swoole_socket_coro_exception_ce, errno,
                "new Socket() failed. Error: %s [%d]", strerror(errno), errno
            );
            delete sock->socket;
            sock->socket = nullptr;
            RETURN_FALSE;
        }
        php_swoole_init_socket(getThis(), sock);
    }
}

static PHP_METHOD(swoole_socket_coro, bind)
{
    char *address;
    size_t l_address;
    zend_long port = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(address, l_address)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    if (!sock->socket->bind(std::string(address, l_address), port))
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, listen)
{
    zend_long backlog = SW_BACKLOG;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(backlog)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    if (!sock->socket->listen(backlog))
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, accept)
{
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    Socket::timeout_setter ts(sock->socket, timeout, SW_TIMEOUT_READ);
    Socket *conn = sock->socket->accept();
    if (conn)
    {
        zend_object *client = swoole_socket_coro_create_object(swoole_socket_coro_ce);
        socket_coro *client_sock = (socket_coro *) swoole_socket_coro_fetch_object(client);
        client_sock->socket = conn;
        ZVAL_OBJ(return_value, &client_sock->std);
        php_swoole_init_socket(return_value, client_sock);
    }
    else
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, connect)
{
    char *host;
    size_t l_host;
    zend_long port = 0;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STRING(host, l_host)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    if (sock->socket->sock_domain == AF_INET6 || sock->socket->sock_domain == AF_INET)
    {
        if (ZEND_NUM_ARGS() == 1)
        {
            swoole_php_error(E_WARNING, "Socket of type AF_INET/AF_INET6 requires port argument");
            RETURN_FALSE;
        }
        else if (port == 0 || port >= 65536)
        {
            swoole_php_error(E_WARNING, "Invalid port argument[" ZEND_LONG_FMT "]", port);
            RETURN_FALSE;
        }
    }
    Socket::timeout_setter ts(sock->socket, timeout, SW_TIMEOUT_CONNECT);
    if (!sock->socket->connect(std::string(host, l_host), port))
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static sw_inline void swoole_socket_coro_recv(INTERNAL_FUNCTION_PARAMETERS, const bool all)
{
    zend_long length = SW_BUFFER_SIZE_BIG;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(length <= 0))
    {
        length = SW_BUFFER_SIZE_BIG;
    }

    swoole_get_socket_coro(sock, getThis());

    zend_string *buf = zend_string_alloc(length, 0);
    Socket::timeout_setter ts(sock->socket, timeout, SW_TIMEOUT_READ);
    ssize_t bytes = all ? sock->socket->recv_all(ZSTR_VAL(buf), length) : sock->socket->recv(ZSTR_VAL(buf), length);
    swoole_socket_coro_sync_properties(getThis(), sock);
    if (UNEXPECTED(bytes < 0))
    {
        zend_string_free(buf);
        RETURN_FALSE;
    }
    else if (UNEXPECTED(bytes == 0))
    {
        zend_string_free(buf);
        RETURN_EMPTY_STRING();
    }
    else
    {
        RETURN_STR(sw_zend_string_recycle(buf, length, bytes));
    }
}

static PHP_METHOD(swoole_socket_coro, recv)
{
    swoole_socket_coro_recv(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_socket_coro, recvAll)
{
    swoole_socket_coro_recv(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static sw_inline void swoole_socket_coro_send(INTERNAL_FUNCTION_PARAMETERS, const bool all)
{
    char *data;
    size_t length;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, length)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    Socket::timeout_setter ts(sock->socket, timeout, SW_TIMEOUT_WRITE);
    ssize_t retval = all ? sock->socket->send_all(data, length) : sock->socket->send(data, length);
    swoole_socket_coro_sync_properties(getThis(), sock);
    if (UNEXPECTED(retval < 0))
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_socket_coro, send)
{
    swoole_socket_coro_send(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_socket_coro, sendAll)
{
    swoole_socket_coro_send(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_METHOD(swoole_socket_coro, recvfrom)
{
    zval *peername;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL_EX(peername, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    zend_string *buf = zend_string_alloc(SW_BUFFER_SIZE_BIG, 0);
    Socket::timeout_setter ts(sock->socket, timeout, SW_TIMEOUT_READ);
    ssize_t bytes = sock->socket->recvfrom(ZSTR_VAL(buf), SW_BUFFER_SIZE_BIG);
    swoole_socket_coro_sync_properties(getThis(), sock);
    if (bytes < 0)
    {
        zend_string_free(buf);
        RETURN_FALSE;
    }
    else if (bytes == 0)
    {
        zend_string_free(buf);
        RETURN_EMPTY_STRING();
    }
    else
    {
        ZSTR_LEN(buf) = bytes;
        ZSTR_VAL(buf)[bytes] = 0;

        zval_dtor(peername);
        array_init(peername);
        if (sock->socket->sock_domain == AF_INET)
        {
            add_assoc_long(peername, "port", swConnection_get_port(sock->socket->socket));
            add_assoc_string(peername, "address", (char *) swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->socket->sock_domain == AF_INET6)
        {
            add_assoc_long(peername, "port", swConnection_get_port(sock->socket->socket));
            add_assoc_string(peername, "address", (char *) swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->socket->sock_domain == AF_UNIX)
        {
            add_assoc_string(peername, "address", (char *) swConnection_get_ip(sock->socket->socket));
        }
        RETURN_STR(buf);
    }
}

static PHP_METHOD(swoole_socket_coro, sendto)
{
    char *data;
    size_t l_data;
    char *addr;
    size_t l_addr;
    zend_long port = 0;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(addr, l_addr)
        Z_PARAM_LONG(port)
        Z_PARAM_STRING(data, l_data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    ssize_t retval = sock->socket->sendto(addr, port, data, l_data);
    swoole_socket_coro_sync_properties(getThis(), sock);
    if (retval < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_socket_coro, shutdown)
{
    zend_long how = SHUT_RDWR;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(how)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_get_socket_coro(sock, getThis());

    if (!sock->socket->shutdown(how))
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, close)
{
    swoole_get_socket_coro(sock, getThis());

#ifdef SWOOLE_SOCKETS_SUPPORT
    if (sock->resource)
    {
        swoole_php_socket_free(sock->resource);
        sock->resource = nullptr;
    }
#endif

    if (sock->socket->close())
    {
        delete sock->socket;
        sock->socket = SW_BAD_SOCKET;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, getsockname)
{
    swSocketAddress info = {{{0}}};
    char addr_str[INET6_ADDRSTRLEN + 1];

    swoole_get_socket_coro(sock, getThis());

    info.len = sizeof(info.addr);

    if (getsockname(sock->socket->get_fd(), (struct sockaddr *) &info.addr, &info.len) != 0)
    {
        sock->socket->set_err(errno);
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }

    array_init(return_value);
    switch (sock->socket->sock_domain)
    {
    case AF_INET6:
        inet_ntop(AF_INET6, &info.addr.inet_v6.sin6_addr, addr_str, INET6_ADDRSTRLEN);
        add_assoc_string(return_value, "address", addr_str);
        add_assoc_long(return_value, "port", htons(info.addr.inet_v6.sin6_port));
        break;
    case AF_INET:
        inet_ntop(AF_INET, &info.addr.inet_v4.sin_addr, addr_str, INET_ADDRSTRLEN);
        add_assoc_string(return_value, "address", addr_str);
        add_assoc_long(return_value, "port", htons(info.addr.inet_v4.sin_port));
        break;
    case AF_UNIX:
        add_assoc_string(return_value, "address", info.addr.un.sun_path);
        break;
    default:
        swoole_php_error(E_WARNING, "unsupported address family %d for socket#%d", sock->socket->sock_domain, sock->socket->get_fd());
        sock->socket->set_err(EOPNOTSUPP);
        swoole_socket_coro_sync_properties(getThis(), sock);
        zval_ptr_dtor(return_value);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, getpeername)
{
    swSocketAddress info = {{{0}}};
    char addr_str[INET6_ADDRSTRLEN + 1];

    swoole_get_socket_coro(sock, getThis());

    if (getpeername(sock->socket->get_fd(), (struct sockaddr *) &info.addr, &info.len) != 0)
    {
        sock->socket->set_err(errno);
        swoole_socket_coro_sync_properties(getThis(), sock);
        RETURN_FALSE;
    }

    array_init(return_value);
    switch (sock->socket->sock_domain)
    {
    case AF_INET6:
        inet_ntop(AF_INET6, &info.addr.inet_v6.sin6_addr, addr_str, INET6_ADDRSTRLEN);
        add_assoc_string(return_value, "address", addr_str);
        add_assoc_long(return_value, "port", htons(info.addr.inet_v6.sin6_port));
        break;
    case AF_INET:
        inet_ntop(AF_INET, &info.addr.inet_v4.sin_addr, addr_str, INET_ADDRSTRLEN);
        add_assoc_string(return_value, "address", addr_str);
        add_assoc_long(return_value, "port", htons(info.addr.inet_v4.sin_port));
        break;
    case AF_UNIX:
        add_assoc_string(return_value, "address", info.addr.un.sun_path);
        break;
    default:
        swoole_php_error(E_WARNING, "unsupported address family %d for socket#%d", sock->socket->sock_domain, sock->socket->get_fd());
        sock->socket->set_err(EOPNOTSUPP);
        swoole_socket_coro_sync_properties(getThis(), sock);
        zval_ptr_dtor(return_value);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, getOption)
{
    struct linger linger_val;
    struct timeval tv;
    socklen_t optlen;
    int other_val;
    zend_long level, optname;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &level, &optname) == FAILURE)
    {
        return;
    }

    swoole_get_socket_coro(sock, getThis());

    if (level == IPPROTO_IP)
    {
        switch (optname)
        {
        case IP_MULTICAST_IF:
        {
            struct in_addr if_addr;
            unsigned int if_index;
            optlen = sizeof(if_addr);
            if (getsockopt(sock->socket->get_fd(), level, optname, (char*) &if_addr, &optlen) != 0)
            {
                swoole_php_sys_error(E_WARNING, "getsockopt(%d, " ZEND_LONG_FMT ", " ZEND_LONG_FMT ")", sock->socket->get_fd(), level, optname);
                RETURN_FALSE;
            }
            if (php_add4_to_if_index(&if_addr, sock->socket, &if_index) == SUCCESS)
            {
                RETURN_LONG((zend_long ) if_index);
            }
            else
            {
                RETURN_FALSE;
            }
        }
        }
    }
    else if (level == IPPROTO_IPV6)
    {
        int ret = php_do_getsockopt_ipv6_rfc3542(sock->socket, level, optname, return_value);
        if (ret == SUCCESS)
        {
            return;
        }
        else if (ret == FAILURE)
        {
            RETURN_FALSE;
        } /* else continue */
    }

    /* sol_socket options and general case */
    switch (optname)
    {
    case SO_LINGER:
        optlen = sizeof(linger_val);

        if (getsockopt(sock->socket->get_fd(), level, optname, (char*) &linger_val, &optlen) != 0)
        {
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, " ZEND_LONG_FMT ", " ZEND_LONG_FMT ")", sock->socket->get_fd(), level, optname);
            RETURN_FALSE;
        }

        array_init(return_value);
        add_assoc_long(return_value, "l_onoff", linger_val.l_onoff);
        add_assoc_long(return_value, "l_linger", linger_val.l_linger);
        break;

    case SO_RCVTIMEO:
    case SO_SNDTIMEO:
        optlen = sizeof(tv);

        if (getsockopt(sock->socket->get_fd(), level, optname, (char*) &tv, &optlen) != 0)
        {
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, " ZEND_LONG_FMT ", " ZEND_LONG_FMT ")", sock->socket->get_fd(), level, optname);
            RETURN_FALSE;
        }

        array_init(return_value);

        add_assoc_long(return_value, "sec", tv.tv_sec);
        add_assoc_long(return_value, "usec", tv.tv_usec);
        break;

    default:
        optlen = sizeof(other_val);

        if (getsockopt(sock->socket->get_fd(), level, optname, (char*) &other_val, &optlen) != 0)
        {
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, " ZEND_LONG_FMT ", " ZEND_LONG_FMT ")", sock->socket->get_fd(), level, optname);
            RETURN_FALSE;
        }
        if (optlen == 1)
        {
            other_val = *((unsigned char *) &other_val);
        }

        RETURN_LONG(other_val);
        break;
    }
}

static PHP_METHOD(swoole_socket_coro, setOption)
{
    zval *arg4;
    struct linger lv;
    int ov, optlen, retval;
    struct timeval tv;
    zend_long level, optname;
    char *opt_ptr;
    HashTable *opt_ht;
    zval *l_onoff, *l_linger;
    zval *sec, *usec;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "llz", &level, &optname, &arg4) == FAILURE)
    {
        return;
    }

    swoole_get_socket_coro(sock, getThis());

#define HANDLE_SUBCALL(res) \
    do { \
        if (res == 1) { goto default_case; } \
        else if (res == SUCCESS) { RETURN_TRUE; } \
        else { RETURN_FALSE; } \
    } while (0)

    if (level == IPPROTO_IP)
    {
        int res = php_do_setsockopt_ip_mcast(sock->socket, level, optname, arg4);
        HANDLE_SUBCALL(res);
    }
    else if (level == IPPROTO_IPV6)
    {
        int res = php_do_setsockopt_ipv6_mcast(sock->socket, level, optname, arg4);
        if (res == 1)
        {
            res = php_do_setsockopt_ipv6_rfc3542(sock->socket, level, optname, arg4);
        }
        HANDLE_SUBCALL(res);
    }

    switch (optname) {
        case SO_LINGER: {
            const char l_onoff_key[] = "l_onoff";
            const char l_linger_key[] = "l_linger";

            convert_to_array_ex(arg4);
            opt_ht = Z_ARRVAL_P(arg4);

            if ((l_onoff = zend_hash_str_find(opt_ht, l_onoff_key, sizeof(l_onoff_key) - 1)) == NULL) {
                php_error_docref(NULL, E_WARNING, "no key \"%s\" passed in optval", l_onoff_key);
                RETURN_FALSE;
            }
            if ((l_linger = zend_hash_str_find(opt_ht, l_linger_key, sizeof(l_linger_key) - 1)) == NULL) {
                php_error_docref(NULL, E_WARNING, "no key \"%s\" passed in optval", l_linger_key);
                RETURN_FALSE;
            }

            convert_to_long_ex(l_onoff);
            convert_to_long_ex(l_linger);

            lv.l_onoff = (unsigned short)Z_LVAL_P(l_onoff);
            lv.l_linger = (unsigned short)Z_LVAL_P(l_linger);

        optlen = sizeof(lv);
        opt_ptr = (char*) &lv;
        break;
        }

        case SO_RCVTIMEO:
        case SO_SNDTIMEO: {
            const char sec_key[] = "sec";
            const char usec_key[] = "usec";

            convert_to_array_ex(arg4);
            opt_ht = Z_ARRVAL_P(arg4);

            if ((sec = zend_hash_str_find(opt_ht, sec_key, sizeof(sec_key) - 1)) == NULL) {
                php_error_docref(NULL, E_WARNING, "no key \"%s\" passed in optval", sec_key);
                RETURN_FALSE;
            }
            if ((usec = zend_hash_str_find(opt_ht, usec_key, sizeof(usec_key) - 1)) == NULL) {
                php_error_docref(NULL, E_WARNING, "no key \"%s\" passed in optval", usec_key);
                RETURN_FALSE;
        }

        convert_to_long_ex(sec);
        convert_to_long_ex(usec);
        tv.tv_sec = Z_LVAL_P(sec);
        tv.tv_usec = Z_LVAL_P(usec);
        sock->socket->set_timeout(&tv,
                optname == SO_RCVTIMEO ? SW_TIMEOUT_READ : SW_TIMEOUT_CONNECT | SW_TIMEOUT_WRITE);
        RETURN_TRUE;
        break;
        }
#ifdef SO_BINDTODEVICE
        case SO_BINDTODEVICE: {
            if (Z_TYPE_P(arg4) == IS_STRING) {
                opt_ptr = Z_STRVAL_P(arg4);
                optlen = Z_STRLEN_P(arg4);
            } else {
                opt_ptr = (char *) "";
                optlen = 0;
            }
            break;
        }
#endif

    default:
        default_case:
        convert_to_long_ex(arg4);
        ov = Z_LVAL_P(arg4);

        optlen = sizeof(ov);
        opt_ptr = (char*) &ov;
        break;
    }

    retval = setsockopt(sock->socket->get_fd(), level, optname, opt_ptr, optlen);
    if (retval != 0)
    {
        swoole_php_sys_error(E_WARNING, "setsockopt(%d) failed", sock->socket->get_fd());
        RETURN_FALSE
    }

    RETURN_TRUE;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_socket_coro, getSocket)
{
    php_socket *socket_object;

    swoole_get_socket_coro(sock, getThis());

    if (sock->resource)
    {
        RETURN_ZVAL(sock->resource, 1, 0);
    }
    socket_object = swoole_convert_to_socket(sock->socket->get_fd());
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void * ) socket_object, php_sockets_le_socket());
    sock->resource = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(sock->resource);
}
#endif
