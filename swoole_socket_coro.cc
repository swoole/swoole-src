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

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "socket.h"
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
    int domain;
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
static PHP_METHOD(swoole_socket_coro, recvfrom);
static PHP_METHOD(swoole_socket_coro, sendto);
static PHP_METHOD(swoole_socket_coro, getpeername);
static PHP_METHOD(swoole_socket_coro, getsockname);
static PHP_METHOD(swoole_socket_coro, close);
#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_socket_coro, getSocket);
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_construct, 0, 0, 3)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, addr)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_socket_coro_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_socket_coro_methods[] =
{
    PHP_ME(swoole_socket_coro, __construct, arginfo_swoole_socket_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, bind, arginfo_swoole_socket_coro_bind, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, listen, arginfo_swoole_socket_coro_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, accept, arginfo_swoole_socket_coro_accept, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, connect, arginfo_swoole_socket_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, recv, arginfo_swoole_socket_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, send, arginfo_swoole_socket_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, recvfrom, arginfo_swoole_socket_coro_recvfrom, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, sendto, arginfo_swoole_socket_coro_sendto, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getpeername, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getsockname, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_socket_coro, getSocket, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_socket_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static sw_inline socket_coro * swoole_socket_coro_fetch_object(zend_object *obj)
{
    return (socket_coro *) ((char *) obj - swoole_socket_coro_handlers.offset);
}

static sw_inline socket_coro * swoole_get_socket_coro(zval *zobject)
{
    socket_coro *sock = swoole_socket_coro_fetch_object(Z_OBJ_P(zobject));
    if (UNEXPECTED(!sock->socket))
    {
        swoole_php_fatal_error(E_ERROR, "you must call Socket constructor first.");
    }
    return sock;
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
    delete sock->socket;
    zend_object_std_dtor(&sock->std);
}

static zend_object *swoole_socket_coro_create_object(zend_class_entry *ce)
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

    zend_declare_property_long(swoole_socket_coro_ce_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);

    SWOOLE_INIT_CLASS_ENTRY_EX(swoole_socket_coro_exception, "Swoole\\Coroutine\\Socket\\Exception", NULL, "Co\\Socket\\Exception", NULL, swoole_exception);
}

static PHP_METHOD(swoole_socket_coro, __construct)
{
    zend_long domain, type, protocol;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(domain)
        Z_PARAM_LONG(type)
        Z_PARAM_LONG(protocol)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_swoole_check_reactor();

    socket_coro *sock = (socket_coro *) swoole_socket_coro_fetch_object(Z_OBJ_P(getThis()));
    sock->socket = new Socket(get_socket_type(domain, type, protocol));
    if (unlikely(sock->socket->socket == nullptr))
    {
        delete sock->socket;
        zend_throw_exception_ex(
            swoole_socket_coro_exception_ce_ptr, errno,
            "new Socket() failed. Error: %s [%d]", strerror(errno), errno
        );
        RETURN_FALSE;
    }
    sock->domain = domain;
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

    socket_coro *sock = swoole_get_socket_coro(getThis());
    if (!sock->socket->bind(std::string(address, l_address), port))
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
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

    socket_coro *sock = swoole_get_socket_coro(getThis());
    if (!sock->socket->listen(backlog))
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, accept)
{
    double timeout = COROG.socket_timeout;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    socket_coro *sock = swoole_get_socket_coro(getThis());
    if (timeout != 0)
    {
        sock->socket->set_timeout(timeout);
    }
    Socket *conn = sock->socket->accept();
    if (conn)
    {
        zend_object *client = swoole_socket_coro_create_object(swoole_socket_coro_ce_ptr);
        socket_coro *client_sock = (socket_coro *) swoole_socket_coro_fetch_object(client);
        client_sock->socket = conn;
        ZVAL_OBJ(return_value, &client_sock->std);
    }
    else
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, recv)
{
    coro_check();

    zend_long length = SW_BUFFER_SIZE_BIG;
    double timeout = COROG.socket_timeout;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (length <= 0)
    {
        length = SW_BUFFER_SIZE_BIG;
    }

    socket_coro *sock = swoole_get_socket_coro(getThis());
    sock->socket->set_timeout(timeout);

    zend_string *buf = zend_string_alloc(length, 0);
    ssize_t bytes = sock->socket->recv(ZSTR_VAL(buf), length);
    if (bytes < 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
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
        RETURN_STR(buf);
    }
}

static PHP_METHOD(swoole_socket_coro, recvfrom)
{
    zval *peername;
    double timeout = COROG.socket_timeout;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL_EX(peername, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    socket_coro *sock = swoole_get_socket_coro(getThis());
    sock->socket->set_timeout(timeout);

    zend_string *buf = zend_string_alloc(SW_BUFFER_SIZE_BIG, 0);
    ssize_t bytes = sock->socket->recvfrom(ZSTR_VAL(buf), SW_BUFFER_SIZE_BIG);
    if (bytes < 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
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
        if (sock->domain == AF_INET)
        {
            add_assoc_long(peername, "port", swConnection_get_port(sock->socket->socket));
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->domain == AF_INET6)
        {
            add_assoc_long(peername, "port", swConnection_get_port(sock->socket->socket));
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
        }
        else if (sock->domain == AF_UNIX)
        {
            add_assoc_string(peername, "address", swConnection_get_ip(sock->socket->socket));
        }
        RETURN_STR(buf);
    }
}

static PHP_METHOD(swoole_socket_coro, send)
{
    double timeout = COROG.socket_timeout;
    char *data;
    size_t l_data;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    socket_coro *sock = swoole_get_socket_coro(getThis());
    ssize_t retval = sock->socket->send(data, l_data);
    if (retval < 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
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

    socket_coro *sock = swoole_get_socket_coro(getThis());
    ssize_t retval = sock->socket->sendto(addr, port, data, l_data);
    if (retval < 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_socket_coro, close)
{
    coro_check();

    socket_coro *sock = swoole_get_socket_coro(getThis());

    if (!sock->socket->close())
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_socket_coro, getsockname)
{
    socket_coro *sock = swoole_get_socket_coro(getThis());
    array_init(return_value);

    swSocketAddress info;
    memset(&info, 0, sizeof(info));
    info.len = sizeof(info.addr);
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getsockname(sock->socket->get_fd(), (struct sockaddr *) &info.addr, &info.len) != 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), errno);
        RETURN_FALSE;
    }

    switch (sock->domain)
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
        swoole_php_error(E_WARNING, "Unsupported address family %d", sock->domain);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, getpeername)
{
    socket_coro *sock = swoole_get_socket_coro(getThis());
    array_init(return_value);

    swSocketAddress info;
    memset(&info, 0, sizeof(info));
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getpeername(sock->socket->get_fd(), (struct sockaddr *) &info.addr, &info.len) != 0)
    {
        zend_update_property_long(swoole_socket_coro_ce_ptr, getThis(), ZEND_STRL("errCode"), errno);
        RETURN_FALSE;
    }

    switch (sock->domain)
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
        swoole_php_error(E_WARNING, "Unsupported address family %d", sock->domain);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, connect)
{
    coro_check();

    socket_coro *sock = swoole_get_socket_coro(getThis());
    char *host;
    size_t l_host;
    zend_long port = 0;
    double timeout = SW_CLIENT_CONNECT_TIMEOUT;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STRING(host, l_host)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (sock->domain == AF_INET6 || sock->domain == AF_INET)
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
    sock->socket->set_timeout(timeout);
    if (sock->socket->connect(std::string(host, l_host), port))
    {
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_socket_coro, getSocket)
{
    socket_coro *sock = swoole_get_socket_coro(getThis());
    php_socket *socket_object = swoole_convert_to_socket(sock->socket->get_fd());
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void * ) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
    sock->resource = zsocket;
}
#endif
#endif
