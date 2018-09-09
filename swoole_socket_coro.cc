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

#ifdef FAST_ZPP
#undef FAST_ZPP
#endif

static zend_class_entry swoole_socket_coro_ce;
static zend_class_entry *swoole_socket_coro_class_entry_ptr;
static zend_object_handlers swoole_socket_coro_handlers;

static zend_class_entry swoole_socket_coro_exception_ce;
static zend_class_entry *swoole_socket_coro_exception_class_entry_ptr;

typedef struct
{
    zval object;
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
    PHP_ME(swoole_socket_coro, __construct, arginfo_swoole_socket_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
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

static inline socket_coro * sw_socket_coro_fetch_object(zend_object *obj)
{
    return (socket_coro *) ((char *) obj - XtOffsetOf(socket_coro, std));
}

#define Z_SOCKET_CORO_OBJ_P(zv) sw_socket_coro_fetch_object(Z_OBJ_P(zv))


static void swoole_socket_coro_free_storage(zend_object *object)
{
    socket_coro *sock = (socket_coro *) sw_socket_coro_fetch_object(object);
    delete sock->socket;
    zend_object_std_dtor(&sock->std);
}

static zend_object *swoole_socket_coro_create(zend_class_entry *ce TSRMLS_DC)
{
    socket_coro *sock = (socket_coro *) ecalloc(1, sizeof(socket_coro) + zend_object_properties_size(ce));
    zend_object_std_init(&sock->std, ce TSRMLS_CC);
    /* Even if you don't use properties yourself you should still call object_properties_init(),
     * because extending classes may use properties. (Generally a lot of the stuff you will do is
     * for the sake of not breaking extending classes). */
    object_properties_init(&sock->std, ce);
    sock->std.handlers = &swoole_socket_coro_handlers;
    return &sock->std;
}

void swoole_socket_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_socket_coro_ce, "Swoole\\Coroutine\\Socket", swoole_socket_coro_methods);

    swoole_socket_coro_class_entry_ptr = zend_register_internal_class(&swoole_socket_coro_ce TSRMLS_CC);
    swoole_socket_coro_class_entry_ptr->ce_flags |= ZEND_ACC_FINAL;
    swoole_socket_coro_class_entry_ptr->create_object = swoole_socket_coro_create;
    swoole_socket_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_socket_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;
    zend_declare_property_long(swoole_socket_coro_class_entry_ptr, SW_STRL("errCode") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    memcpy(&swoole_socket_coro_handlers, zend_get_std_object_handlers(), sizeof(swoole_socket_coro_handlers));
    swoole_socket_coro_handlers.free_obj = swoole_socket_coro_free_storage;
    swoole_socket_coro_handlers.clone_obj = NULL;
    swoole_socket_coro_handlers.offset = XtOffsetOf(socket_coro, std);

    INIT_CLASS_ENTRY(swoole_socket_coro_exception_ce, "Swoole\\Coroutine\\Socket\\Exception", NULL);
    swoole_socket_coro_exception_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_socket_coro_exception_ce,
            zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Socket", swoole_socket_coro_class_entry_ptr);
        sw_zend_register_class_alias("Co\\Socket\\Exception", swoole_socket_coro_exception_class_entry_ptr);
    }
}

static PHP_METHOD(swoole_socket_coro, __construct)
{
    zend_long domain, type, protocol;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(domain);
        Z_PARAM_LONG(type);
        Z_PARAM_LONG(protocol);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lll", &domain, &type, &protocol) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    php_swoole_check_reactor();

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis()) ;
    sock->socket = new Socket(get_socket_type(domain, type, protocol));
    sock->domain = domain;
    sock->object = *getThis();
}

static PHP_METHOD(swoole_socket_coro, bind)
{
    char *address;
    size_t l_address;
    zend_long port = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(address, l_address);
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &address, &l_address, &port) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    if (!sock->socket->bind(std::string(address, l_address), port))
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, listen)
{
    zend_long backlog = SW_BACKLOG;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(backlog);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &backlog) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    if (!sock->socket->listen(backlog))
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, accept)
{
    double timeout = -1;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    if (timeout != 0)
    {
        sock->socket->setTimeout(timeout);
    }
    Socket *conn = sock->socket->accept();
    if (conn)
    {
        zend_object *client = swoole_socket_coro_create(swoole_socket_coro_class_entry_ptr);
        socket_coro *client_sock = (socket_coro *) sw_socket_coro_fetch_object(client);
        client_sock->socket = conn;
        ZVAL_OBJ(return_value, &client_sock->std);
    }
    else
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_socket_coro, recv)
{
    coro_check(TSRMLS_C);

    long length = SW_BUFFER_SIZE_BIG;
    double timeout = -1;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(length);
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ld", &length, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    if (length <= 0)
    {
        length = SW_BUFFER_SIZE_BIG;
    }

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    sock->socket->setTimeout(timeout);

    zend_string *buf = zend_string_alloc(length, 0);
    ssize_t bytes = sock->socket->recv(ZSTR_VAL(buf), length);
    if (bytes < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
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
    double timeout = -1;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(peername);
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/|d", &peername, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    sock->socket->setTimeout(timeout);

    zend_string *buf = zend_string_alloc(SW_BUFFER_SIZE_BIG, 0);
    ssize_t bytes = sock->socket->recvfrom(ZSTR_VAL(buf), SW_BUFFER_SIZE_BIG);
    if (bytes < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
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
    double timeout = -1;
    char *data;
    size_t l_data;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, l_data);
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|d", &data, &l_data, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    ssize_t retval = sock->socket->send(data, l_data);
    if (retval < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
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

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(addr, l_addr);
        Z_PARAM_LONG(port);
        Z_PARAM_STRING(data, l_data);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &addr, &l_addr, &port, &data, &l_data) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    ssize_t retval = sock->socket->sendto(addr, port, data, l_data);
    if (retval < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_socket_coro, close)
{
    coro_check(TSRMLS_C);

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());

    if (sock->socket->close())
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), sock->socket->errCode TSRMLS_CC);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_socket_coro, getsockname)
{
    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    array_init(return_value);

    swSocketAddress info;
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getsockname(sock->socket->get_fd(), (struct sockaddr *) &info.addr.inet_v4, &info.len) != 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errno TSRMLS_CC);
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
    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    array_init(return_value);

    swSocketAddress info;
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getpeername(sock->socket->get_fd(), (struct sockaddr *) &info.addr, &info.len) != 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errno TSRMLS_CC);
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
    coro_check(TSRMLS_C);

    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    char *host;
    size_t l_host;
    zend_long port = 0;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STRING(host, l_host);
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port);
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ld", &host, &l_host, &port, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
#endif

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
    sock->socket->setTimeout(timeout);
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
    socket_coro *sock = (socket_coro *) Z_SOCKET_CORO_OBJ_P(getThis());
    php_socket *socket_object = swoole_convert_to_socket(sock->socket->get_fd());
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void * ) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    sw_zval_add_ref(&zsocket);
    sock->resource = zsocket;
}
#endif
#endif
