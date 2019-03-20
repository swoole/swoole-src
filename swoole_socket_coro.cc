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

#include "swoole_coroutine.h"
#include "thirdparty/sockets/php_sockets_cxx.h"

#include <string>

using namespace swoole;

static zend_class_entry swoole_socket_coro_ce;
static zend_class_entry *swoole_socket_coro_ce_ptr;
static zend_object_handlers swoole_socket_coro_handlers;

static zend_class_entry swoole_socket_coro_exception_ce;
static zend_class_entry *swoole_socket_coro_exception_ce_ptr;
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
            swoole_php_fatal_error(E_ERROR, "you must call Socket constructor first."); \
        } \
        if (UNEXPECTED(_sock->socket == SW_BAD_SOCKET)) { \
            zend_update_property_long(swoole_socket_coro_ce_ptr, _zobject, ZEND_STRL("errCode"), EBADF); \
            zend_update_property_string(swoole_socket_coro_ce_ptr, _zobject, ZEND_STRL("errMsg"), strerror(EBADF)); \
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
        sw_zval_free(sock->resource);
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

void swoole_socket_coro_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_socket_coro, "Swoole\\Coroutine\\Socket", NULL, "Co\\Socket", swoole_socket_coro_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_socket_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_socket_coro, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_socket_coro, zend_class_unset_property_deny);
    SWOOLE_SET_CLASS_CUSTOM_OBJECT(swoole_socket_coro, swoole_socket_coro_create_object, swoole_socket_coro_free_object, socket_coro, std);

    zend_declare_property_long(swoole_socket_coro_ce_ptr, ZEND_STRL("fd"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_socket_coro_ce_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_socket_coro_ce_ptr, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);

    SWOOLE_INIT_CLASS_ENTRY_EX(swoole_socket_coro_exception, "Swoole\\Coroutine\\Socket\\Exception", NULL, "Co\\Socket\\Exception", NULL, swoole_exception);
}

static sw_inline void swoole_socket_coro_sync_properties(zval *zobject, socket_coro *sock)
{
    zend_update_property_long(swoole_socket_coro_ce_ptr, zobject, ZEND_STRL("errCode"), sock->socket->errCode);
    zend_update_property_string(swoole_socket_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), sock->socket->errMsg);
}

static void sw_inline php_swoole_init_socket(zval *zobject, socket_coro *sock)
{
    zend_update_property_long(swoole_socket_coro_ce_ptr, zobject, ZEND_STRL("fd"), sock->socket->get_fd());
}

SW_API bool php_swoole_export_socket(zval *zobject, int fd, enum swSocket_type type)
{
    zend_object *object = swoole_socket_coro_create_object(swoole_socket_coro_ce_ptr);
    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(object);

    php_swoole_check_reactor();
    sock->socket = new Socket(fd, type);
    if (UNEXPECTED(sock->socket->socket == nullptr))
    {
        swoole_php_fatal_error(E_WARNING, "new Socket() failed. Error: %s [%d]", strerror(errno), errno);
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
                swoole_socket_coro_exception_ce_ptr, errno,
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
        zend_object *client = swoole_socket_coro_create_object(swoole_socket_coro_ce_ptr);
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

static sw_inline void swoole_socket_coro_recv(INTERNAL_FUNCTION_PARAMETERS, bool all)
{
    zend_long length = SW_BUFFER_SIZE_BIG;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (length <= 0)
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
        ZSTR_LEN(buf) = bytes;
        ZSTR_VAL(buf)[bytes] = '\0';
        RETURN_STR(buf);
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
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->socket->sock_domain == AF_INET6)
        {
            add_assoc_long(peername, "port", swConnection_get_port(sock->socket->socket));
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->socket->sock_domain == AF_UNIX)
        {
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
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

    bool can_be_deleted = sock->socket->close();
    bool success = sock->socket->errCode == 0;
    if (UNEXPECTED(!success))
    {
        swoole_socket_coro_sync_properties(getThis(), sock);
    }
    if (can_be_deleted)
    {
        delete sock->socket;
        sock->socket = SW_BAD_SOCKET;
    }
    RETURN_BOOL(success);
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
                swoole_php_sys_error(E_WARNING, "getsockopt(%d, %ld, %ld)", sock->socket->get_fd(), level, optname);
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
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, %ld, %ld)", sock->socket->get_fd(), level, optname);
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
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, %ld, %ld)", sock->socket->get_fd(), level, optname);
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
            swoole_php_sys_error(E_WARNING, "getsockopt(%d, %ld, %ld)", sock->socket->get_fd(), level, optname);
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
                opt_ptr = "";
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
        swoole_php_sys_error(E_WARNING, "setsockopt(%d) failed.", sock->socket->get_fd());
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
