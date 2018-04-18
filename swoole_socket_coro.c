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
#endif

static zend_class_entry swoole_socket_coro_ce;
static zend_class_entry *swoole_socket_coro_class_entry_ptr;
static zend_object_handlers swoole_socket_coro_handlers;

enum socket_opcode
{
    SW_SOCKET_OPCODE_ACCEPT,
    SW_SOCKET_OPCODE_CONNECT,
    SW_SOCKET_OPCODE_RECV,
    SW_SOCKET_OPCODE_SEND,
};

typedef struct
{
    zend_object std;
    zval object;
    int fd;
    int domain;
    enum socket_opcode opcode;
    char *buf;
    uint32_t buf_size;
    php_context context;
    swTimer_node *timer;
} socket_coro;

static PHP_METHOD(swoole_socket_coro, __construct);
static PHP_METHOD(swoole_socket_coro, bind);
static PHP_METHOD(swoole_socket_coro, listen);
static PHP_METHOD(swoole_socket_coro, accept);
static PHP_METHOD(swoole_socket_coro, connect);
static PHP_METHOD(swoole_socket_coro, recv);
static PHP_METHOD(swoole_socket_coro, send);
static PHP_METHOD(swoole_socket_coro, getpeername);
static PHP_METHOD(swoole_socket_coro, getsockname);
static PHP_METHOD(swoole_socket_coro, close);

static int swoole_socket_connect(socket_coro *sock, char *host, size_t l_host, int port);
static void socket_onTimeout(swTimer *timer, swTimer_node *tnode);

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
    PHP_ME(swoole_socket_coro, getpeername, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, getsockname, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_socket_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object *swoole_socket_coro_create(zend_class_entry *ce)
{
    socket_coro *sock = emalloc(sizeof(socket_coro));
    bzero(sock, sizeof(socket_coro));

    zend_object_std_init(&sock->std, ce);
    sock->std.handlers = &swoole_socket_coro_handlers;

    return &sock->std;
}

static int socket_onReadable(swReactor *reactor, swEvent *event)
{
    socket_coro *sock = (socket_coro *) event->socket->object;
    php_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    reactor->del(reactor, sock->fd);

    if (sock->timer)
    {
        swTimer_del(&SwooleG.timer, sock->timer);
        sock->timer = NULL;
    }

    switch (sock->opcode)
    {
    case SW_SOCKET_OPCODE_ACCEPT:
    {
        int conn;
#ifdef HAVE_ACCEPT4
        conn = accept4(sock->fd, (struct sockaddr *) &client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        conn = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
        if (conn >= 0)
        {
            swoole_fcntl_set_option(conn, 1, 1);
        }
#endif
        if (conn >= 0)
        {
            object_init_ex(&result, swoole_socket_coro_class_entry_ptr);
            socket_coro *client_sock = (socket_coro *) Z_OBJ(result);
            client_sock->fd = conn;
            client_sock->domain = sock->domain;
        }
        else
        {
            zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
            ZVAL_FALSE(&result);
        }
        break;
    }
    case SW_SOCKET_OPCODE_RECV:
    {
        int n = recv(sock->fd, sock->buf, sock->buf_size, MSG_DONTWAIT);
        if (n < 0)
        {
            zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
            ZVAL_FALSE(&result);
        }
        else if (n == 0)
        {
            ZVAL_EMPTY_STRING(&result);
        }
        else
        {
            ZVAL_STRINGL(&result, sock->buf, n);
        }
        break;
    }
    default:
        break;
    }

    int ret = coro_resume(context, &result, &retval);
    zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

static int socket_onWritable(swReactor *reactor, swEvent *event)
{
    socket_coro *sock = (socket_coro *) event->socket->object;
    php_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    reactor->del(reactor, sock->fd);

    if (sock->timer)
    {
        swTimer_del(&SwooleG.timer, sock->timer);
        sock->timer = NULL;
    }

    switch (sock->opcode)
    {
    case SW_SOCKET_OPCODE_SEND:
    {
        int n = send(sock->fd, Z_STRVAL(context->coro_params), Z_STRLEN(context->coro_params), MSG_DONTWAIT);
        if (n < 0)
        {
            zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
            ZVAL_FALSE(&result);
            break;
        }
        else
        {
            ZVAL_LONG(&result, n);
        }
        break;
    }
    case SW_SOCKET_OPCODE_CONNECT:
    {
        socklen_t len = sizeof(SwooleG.error);
        if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
        {
            zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), errno TSRMLS_CC);
            ZVAL_FALSE(&result);
            break;
        }
        if (SwooleG.error == 0)
        {
            ZVAL_TRUE(&result);
        }
        else
        {
            zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
            ZVAL_FALSE(&result);
        }
        break;
    }
    default:
        break;
    }

    int ret = coro_resume(context, &result, &retval);
    zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    return SW_OK;
}

static void socket_onResolveCompleted(swAio_event *event)
{
    socket_coro *sock = event->object;
    php_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    if (event->error == 0)
    {
        if (swoole_socket_connect(sock, event->buf, strlen(event->buf), Z_LVAL(context->coro_params)) == -1 && errno == EINPROGRESS)
        {
            efree(event->buf);
            if (context->private_data)
            {
                int ms = (int) (Z_DVAL_P((zval *) context->private_data) * 1000);
                php_swoole_check_timer(ms);
                sock->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, sock, socket_onTimeout);
                efree(context->private_data);
                context->private_data = NULL;
            }
            if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock->fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_WRITE) < 0)
            {
                goto _error;
            }
            else
            {
                swConnection *_socket = swReactor_get(SwooleG.main_reactor, sock->fd);
                _socket->object = sock;
                return;
            }
        }
        goto _error;
    }
    else
    {
        _error:
        ZVAL_FALSE(&result);
        efree(event->buf);
        int ret = coro_resume(context, &result, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
}

static void socket_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    socket_coro *sock = (socket_coro *) tnode->data;
    php_context *context = &sock->context;
    sock->timer = NULL;
    SwooleG.main_reactor->del(SwooleG.main_reactor, sock->fd);

    zval *retval = NULL;
    zval result;
    zend_update_property_long(swoole_socket_coro_class_entry_ptr, &sock->object, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
    ZVAL_FALSE(&result);

    int ret = coro_resume(context, &result, &retval);
    zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void swoole_socket_coro_free_storage(zend_object *object)
{
    socket_coro *sock = (socket_coro*) object;
    if (sock->fd >= 0)
    {
        SwooleG.main_reactor->close(SwooleG.main_reactor, sock->fd);
    }
    if (sock->buf)
    {
        efree(sock->buf);
        sock->buf = NULL;
    }
    zend_object_std_dtor(&sock->std);
}

static int swoole_socket_connect(socket_coro *sock, char *host, size_t l_host, int port)
{
    switch (sock->domain)
    {
    case AF_INET:
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        socklen_t len = sizeof(addr);

        if (!inet_pton(AF_INET, host, &addr.sin_addr))
        {
            return -2;
        }
        else
        {
            return connect(sock->fd, (struct sockaddr *) &addr, len);
        }
    }
    case AF_INET6:
    {
        struct sockaddr_in6 addr;
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        socklen_t len = sizeof(addr);

        if (!inet_pton(AF_INET6, host, &addr.sin6_addr))
        {
            return -1;
        }
        else
        {
            return connect(sock->fd, (struct sockaddr *) &addr, len);
        }
    }
    case AF_UNIX:
    {
        struct sockaddr_un s_un = { 0 };
        if (l_host >= sizeof(s_un.sun_path))
        {
            return -1;
        }

        s_un.sun_family = AF_UNIX;
        memcpy(&s_un.sun_path, host, l_host);
        return connect(sock->fd, (struct sockaddr *) &s_un, (socklen_t) (XtOffsetOf(struct sockaddr_un, sun_path) + l_host));
    }

    default:
        break;
    }
    return -3;
}

void swoole_socket_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_socket_coro_ce, "Swoole\\Coroutine\\Socket", swoole_socket_coro_methods);

    swoole_socket_coro_class_entry_ptr = zend_register_internal_class(&swoole_socket_coro_ce);
    swoole_socket_coro_class_entry_ptr->ce_flags |= ZEND_ACC_FINAL;
    swoole_socket_coro_class_entry_ptr->create_object = swoole_socket_coro_create;
    swoole_socket_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_socket_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Socket", swoole_socket_coro_class_entry_ptr);
    }

    memcpy(&swoole_socket_coro_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    swoole_socket_coro_handlers.free_obj = swoole_socket_coro_free_storage;
    swoole_socket_coro_handlers.clone_obj = NULL;

    zend_declare_property_long(swoole_socket_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
}

static PHP_METHOD(swoole_socket_coro, __construct)
{
    zend_long domain, type, protocol;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(domain);
        Z_PARAM_LONG(type);
        Z_PARAM_LONG(protocol);
    ZEND_PARSE_PARAMETERS_END();

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    sock->fd = socket(domain, type, protocol);
    sock->domain = domain;
    sock->object = *getThis();

    if (sock->fd < 0)
    {
        php_error_docref(NULL, E_WARNING, "Unable to create socket [%d]: %s", errno, strerror(errno));
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_SOCKET))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_SOCKET | SW_EVENT_READ, socket_onReadable);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_SOCKET | SW_EVENT_WRITE, socket_onWritable);
    }

    swSetNonBlock(sock->fd);
}

static PHP_METHOD(swoole_socket_coro, bind)
{
    char *address;
    size_t l_address;
    zend_long port;

    struct sockaddr_storage sa_storage = {0};
    struct sockaddr *sock_type = (struct sockaddr*) &sa_storage;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(address, l_address);
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port);
    ZEND_PARSE_PARAMETERS_END();

    int retval;

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    switch (sock->domain)
    {
    case AF_UNIX:
    {    struct sockaddr_un *sa = (struct sockaddr_un *) sock_type;
        sa->sun_family = AF_UNIX;

        if (l_address >= sizeof(sa->sun_path))
        {
            swoole_php_error(E_WARNING, "invalid path: too long (maximum size is %d)", (int )sizeof(sa->sun_path) - 1);
            RETURN_FALSE;
        }
        memcpy(&sa->sun_path, address, l_address);

        retval = bind(sock->fd, (struct sockaddr *) sa,
        offsetof(struct sockaddr_un, sun_path) + l_address);
        break;
    }

    case AF_INET:
    {
        struct sockaddr_in *sa = (struct sockaddr_in *) sock_type;
        sa->sin_family = AF_INET;
        sa->sin_port = htons((unsigned short) port);
        if (!inet_aton(address, &sa->sin_addr))
        {
            RETURN_FALSE;
        }
        retval = bind(sock->fd, (struct sockaddr *) sa, sizeof(struct sockaddr_in));
        break;
    }

    case AF_INET6:
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) sock_type;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((unsigned short) port);

        if (!inet_pton(AF_INET6, address, &sa->sin6_addr))
        {
            RETURN_FALSE;
        }
        retval = bind(sock->fd, (struct sockaddr *)sa, sizeof(struct sockaddr_in6));
        break;
    }
    default:
        RETURN_FALSE;
    }

    if (retval != 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, listen)
{
    zend_long backlog = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(backlog);
    ZEND_PARSE_PARAMETERS_END();

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    if (listen(sock->fd, backlog) != 0)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_socket_coro, accept)
{
    coro_check(TSRMLS_C);

    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock->fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_READ) < 0)
    {
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, sock->fd);
    _socket->object = sock;

    php_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->onTimeout = NULL;
    sock->opcode = SW_SOCKET_OPCODE_ACCEPT;

    if (timeout > 0)
    {
        int ms = (int) (timeout * 1000);
        php_swoole_check_timer(ms);
        sock->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, sock, socket_onTimeout);
    }

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_socket_coro, recv)
{
    coro_check(TSRMLS_C);

    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    if (sock->buf == NULL)
    {
        sock->buf_size = SW_BUFFER_SIZE_BIG;
        sock->buf = emalloc(sock->buf_size);
    }

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock->fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_READ) < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errno TSRMLS_CC);
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, sock->fd);
    _socket->object = sock;

    php_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->onTimeout = NULL;
    sock->opcode = SW_SOCKET_OPCODE_RECV;

    if (timeout > 0)
    {
        int ms = (int) (timeout * 1000);
        php_swoole_check_timer(ms);
        sock->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, sock, socket_onTimeout);
    }

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_socket_coro, send)
{
    coro_check(TSRMLS_C);

    double timeout = -1;
    zval *data;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(data);
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();

    if (Z_TYPE_P(data) != IS_STRING)
    {
        RETURN_FALSE;
    }

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    int ret = send(sock->fd, Z_STRVAL_P(data), Z_STRLEN_P(data), MSG_DONTWAIT);
    if (ret < 0)
    {
        if (errno == EAGAIN)
        {
            goto _yield;
        }
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errno TSRMLS_CC);
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, sock->fd);
    _socket->object = sock;

    _yield:
    if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock->fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_WRITE) < 0)
    {
        zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), errno TSRMLS_CC);
        RETURN_FALSE;
    }

    php_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->onTimeout = NULL;
    context->coro_params = *data;
    sock->opcode = SW_SOCKET_OPCODE_SEND;

    if (timeout > 0)
    {
        int ms = (int) (timeout * 1000);
        php_swoole_check_timer(ms);
        sock->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, sock, socket_onTimeout);
    }

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_socket_coro, close)
{
    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    if (sock->fd < 0)
    {
        RETURN_FALSE;
    }
    int ret = SwooleG.main_reactor->close(SwooleG.main_reactor, sock->fd);
    sock->fd = -1;
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_socket_coro, getsockname)
{
    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    array_init(return_value);

    swSocketAddress info;
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getsockname(sock->fd, &info.addr.inet_v4, &info.len) != 0)
    {
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
    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    array_init(return_value);

    swSocketAddress info;
    char addr_str[INET6_ADDRSTRLEN + 1];

    if (getpeername(sock->fd, &info.addr.inet_v4, &info.len) != 0)
    {
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

    socket_coro *sock = (socket_coro *) Z_OBJ_P(getThis());
    char *host;
    size_t l_host;
    zend_long port = 0;
    double timeout;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STRING(host, l_host);
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port);
        Z_PARAM_DOUBLE(timeout);
    ZEND_PARSE_PARAMETERS_END();

    if (sock->domain == AF_INET6 || sock->domain == AF_INET)
    {
        if (ZEND_NUM_ARGS() == 1)
        {
            swoole_php_error(E_WARNING, "Socket of type AF_INET/AF_INET6 requires port argument");
            RETURN_FALSE;
        }
        else if (port == 0 || port >= 65536)
        {
            swoole_php_error(E_WARNING, "Invalid port argument[%d]", port);
            RETURN_FALSE;
        }
    }

    int retval = swoole_socket_connect(sock, host, l_host, port);
    if (retval == -2)
    {
        swAio_event ev;
        bzero(&ev, sizeof(swAio_event));

        ev.nbytes = l_host < SW_IP_MAX_LENGTH ? SW_IP_MAX_LENGTH : l_host + 1;
        ev.buf = emalloc(ev.nbytes);
        if (!ev.buf)
        {
            swWarn("malloc failed.");
            RETURN_FALSE;
        }

        memcpy(ev.buf, host, l_host);
        ((char *) ev.buf)[l_host] = 0;
        ev.flags = sock->domain;
        ev.type = SW_AIO_GETHOSTBYNAME;
        ev.object = sock;
        ev.callback = socket_onResolveCompleted;

        if (SwooleAIO.mode == SW_AIO_LINUX)
        {
            SwooleAIO.mode = SW_AIO_BASE;
            SwooleAIO.init = 0;
        }
        php_swoole_check_aio();

        if (swAio_dispatch(&ev) < 0)
        {
            efree(ev.buf);
            RETURN_FALSE
        }
        else
        {
            ZVAL_LONG(&sock->context.coro_params, port);
            zval *ztimeout;
            if (timeout > 0)
            {
                ztimeout = emalloc(sizeof(zval));
                ZVAL_DOUBLE(ztimeout, timeout);
                sock->context.private_data = ztimeout;
            }
            else
            {
                sock->context.private_data = NULL;
            }
            goto _yield;
        }
    }
    else if (retval == -1)
    {
        if (errno == EINPROGRESS)
        {
            if (SwooleG.main_reactor->add(SwooleG.main_reactor, sock->fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_WRITE) < 0)
            {
                goto _error;
            }

            swConnection *_socket = swReactor_get(SwooleG.main_reactor, sock->fd);
            _socket->object = sock;

            if (timeout > 0)
            {
                int ms = (int) (timeout * 1000);
                php_swoole_check_timer(ms);
                sock->timer = SwooleG.timer.add(&SwooleG.timer, ms, 0, sock, socket_onTimeout);
            }

            php_context *context;
            _yield: context = &sock->context;
            context->state = SW_CORO_CONTEXT_RUNNING;
            context->onTimeout = NULL;
            sock->opcode = SW_SOCKET_OPCODE_CONNECT;

            coro_save(context);
            coro_yield();
        }
        else
        {
            _error: zend_update_property_long(swoole_socket_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"),
                    errno TSRMLS_CC);
        }
    }
    RETURN_FALSE;
}
