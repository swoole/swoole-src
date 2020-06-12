/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author:   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
 */
#include "php_swoole_cxx.h"

#include "thirdparty/php/standard/proc_open.h"
#include <unordered_map>
#include <initializer_list>

/* openssl */
#ifndef OPENSSL_NO_TLS1_METHOD
#define HAVE_TLS1 1
#endif
#ifndef OPENSSL_NO_TLS1_1_METHOD
#define HAVE_TLS11 1
#endif
#ifndef OPENSSL_NO_TLS1_2_METHOD
#define HAVE_TLS12 1
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000 && !defined(OPENSSL_NO_TLS1_3)
#define HAVE_TLS13 1
#endif
#ifndef OPENSSL_NO_ECDH
#define HAVE_ECDH 1
#endif
#ifndef OPENSSL_NO_TLSEXT
#define HAVE_TLS_SNI 1
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define HAVE_TLS_ALPN 1
#endif
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
#define HAVE_SEC_LEVEL 1
#endif

using namespace swoole;
using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_runtime, enableCoroutine);
static PHP_METHOD(swoole_runtime, getHookFlags);
static PHP_METHOD(swoole_runtime, setHookFlags);
static PHP_FUNCTION(swoole_sleep);
static PHP_FUNCTION(swoole_usleep);
static PHP_FUNCTION(swoole_time_nanosleep);
static PHP_FUNCTION(swoole_time_sleep_until);
static PHP_FUNCTION(swoole_stream_select);
static PHP_FUNCTION(swoole_stream_socket_pair);
static PHP_FUNCTION(swoole_user_func_handler);
SW_EXTERN_C_END

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam);
#if PHP_VERSION_ID < 70400
static size_t socket_read(php_stream *stream, char *buf, size_t count);
static size_t socket_write(php_stream *stream, const char *buf, size_t count);
#else
static ssize_t socket_read(php_stream *stream, char *buf, size_t count);
static ssize_t socket_write(php_stream *stream, const char *buf, size_t count);
#endif
static int socket_flush(php_stream *stream);
static int socket_close(php_stream *stream, int close_handle);
static int socket_stat(php_stream *stream, php_stream_statbuf *ssb);
static int socket_cast(php_stream *stream, int castas, void **ret);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_runtime_enableCoroutine, 0, 0, 0)
    ZEND_ARG_INFO(0, enable)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_runtime_setHookFlags, 0, 0, 1)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

static zend_class_entry *swoole_runtime_ce;

static php_stream_ops socket_ops
{
    socket_write,
    socket_read,
    socket_close,
    socket_flush,
    "tcp_socket/coroutine",
    nullptr, /* seek */
    socket_cast,
    socket_stat,
    socket_set_option,
};

struct php_swoole_netstream_data_t
{
    php_netstream_data_t stream;
    Socket *socket;
};

static bool hook_init = false;
static int hook_flags = 0;

static struct
{
    php_stream_transport_factory tcp;
    php_stream_transport_factory udp;
    php_stream_transport_factory _unix;
    php_stream_transport_factory udg;
    php_stream_transport_factory ssl;
    php_stream_transport_factory tls;
} ori_factory = {
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};

static php_stream_wrapper ori_php_plain_files_wrapper;

#if PHP_VERSION_ID < 70200
typedef void (*zif_handler)(INTERNAL_FUNCTION_PARAMETERS);
#endif

#define SW_HOOK_FUNC(f)       hook_func(ZEND_STRL(#f), PHP_FN(swoole_##f))
#define SW_UNHOOK_FUNC(f)     unhook_func(ZEND_STRL(#f))

static void hook_func(const char *name, size_t l_name, zif_handler handler = nullptr);
static void unhook_func(const char *name, size_t l_name);

static zend_array *function_table = nullptr;

SW_EXTERN_C_BEGIN
#include "ext/standard/file.h"
#include "thirdparty/php/streams/plain_wrapper.c"
SW_EXTERN_C_END

static const zend_function_entry swoole_runtime_methods[] =
{
    PHP_ME(swoole_runtime, enableCoroutine, arginfo_swoole_runtime_enableCoroutine, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_runtime, getHookFlags, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_runtime, setHookFlags, arginfo_swoole_runtime_setHookFlags, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void php_swoole_runtime_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY_BASE(swoole_runtime, "Swoole\\Runtime", "swoole_runtime", nullptr, swoole_runtime_methods, nullptr);
    SW_SET_CLASS_CREATE(swoole_runtime, sw_zend_create_object_deny);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_TCP", SW_HOOK_TCP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_UDP", SW_HOOK_UDP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_UNIX", SW_HOOK_UNIX);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_UDG", SW_HOOK_UDG);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_SSL", SW_HOOK_SSL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_TLS", SW_HOOK_TLS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_STREAM_FUNCTION", SW_HOOK_STREAM_FUNCTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_STREAM_SELECT", SW_HOOK_STREAM_FUNCTION); // backward compatibility
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_FILE", SW_HOOK_FILE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_SLEEP", SW_HOOK_SLEEP);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_PROC", SW_HOOK_PROC);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_CURL", SW_HOOK_CURL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_BLOCKING_FUNCTION", SW_HOOK_BLOCKING_FUNCTION);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HOOK_ALL", SW_HOOK_ALL);

    swoole_proc_open_init(module_number);
}

struct real_func
{
    zend_function *function;
    zif_handler ori_handler;
    zend_fcall_info_cache *fci_cache;
    zval name;
};

void php_swoole_runtime_rshutdown()
{
    if (!hook_init)
    {
        return;
    }

    hook_init = false;

    void *ptr;
    ZEND_HASH_FOREACH_PTR(function_table, ptr)
    {
        real_func *rf = static_cast<real_func *>(ptr);
        /**
         * php library function
         */
        if (rf->fci_cache)
        {
            zval_dtor(&rf->name);
            efree(rf->fci_cache);
        }
        rf->function->internal_function.handler = rf->ori_handler;
        efree(rf);
    }
    ZEND_HASH_FOREACH_END();
    zend_hash_destroy(function_table);
    efree(function_table);
    function_table = nullptr;
}

static inline char *parse_ip_address_ex(const char *str, size_t str_len, int *portno, int get_err, zend_string **err)
{
    char *colon;
    char *host = nullptr;
    char *p;

    if (*(str) == '[' && str_len > 1)
    {
        /* IPV6 notation to specify raw address with port (i.e. [fe80::1]:80) */
        p = (char*) memchr(str + 1, ']', str_len - 2);
        if (!p || *(p + 1) != ':')
        {
            if (get_err)
            {
                *err = strpprintf(0, "Failed to parse IPv6 address \"%s\"", str);
            }
            return nullptr;
        }
        *portno = atoi(p + 2);
        return estrndup(str + 1, p - str - 1);
    }
    if (str_len)
    {
        colon = (char*) memchr(str, ':', str_len - 1);
    }
    else
    {
        colon = nullptr;
    }
    if (colon)
    {
        *portno = atoi(colon + 1);
        host = estrndup(str, colon - str);
    }
    else
    {
        if (get_err)
        {
            *err = strpprintf(0, "Failed to parse address \"%s\"", str);
        }
        return nullptr;
    }

    return host;
}

#if PHP_VERSION_ID < 70400
static size_t socket_write(php_stream *stream, const char *buf, size_t count)
#else
static ssize_t socket_write(php_stream *stream, const char *buf, size_t count)
#endif
{
    php_swoole_netstream_data_t *abstract;
    Socket *sock;
    ssize_t didwrite = -1;

    abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        goto _exit;
    }

    sock = (Socket*) abstract->socket;
    if (UNEXPECTED(!sock))
    {
        goto _exit;
    }

    didwrite = sock->send_all(buf, count);

    if (didwrite > 0)
    {
        php_stream_notify_progress_increment(PHP_STREAM_CONTEXT(stream), didwrite, 0);
    }
    if (didwrite != count)
    {
        php_error_docref(
            NULL, E_NOTICE, "Send of " ZEND_LONG_FMT " bytes failed with errno=%d %s",
            (zend_long) count, sock->errCode, sock->errMsg
        );
        abstract->stream.timeout_event = (sock->errCode == ETIMEDOUT);
    }

    _exit:
#if PHP_VERSION_ID < 70400
    if (didwrite < 0)
    {
        didwrite = 0;
    }
#endif
    return didwrite;
}

#if PHP_VERSION_ID < 70400
static size_t socket_read(php_stream *stream, char *buf, size_t count)
#else
static ssize_t socket_read(php_stream *stream, char *buf, size_t count)
#endif
{
    php_swoole_netstream_data_t *abstract;
    Socket *sock;
    ssize_t nr_bytes = -1;

    abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        goto _exit;
    }

    sock = (Socket*) abstract->socket;
    if (UNEXPECTED(!sock))
    {
        goto _exit;
    }

    nr_bytes = sock->recv(buf, count);

    /**
     * sock->errCode != ETIMEDOUT : Compatible with sync blocking IO
     */
    stream->eof = (nr_bytes == 0 || (nr_bytes == -1 && sock->errCode != ETIMEDOUT && swSocket_error(sock->errCode) == SW_CLOSE));
    if (nr_bytes > 0)
    {
        php_stream_notify_progress_increment(PHP_STREAM_CONTEXT(stream), nr_bytes, 0);
    }

    _exit:
#if PHP_VERSION_ID < 70400
    if (nr_bytes < 0)
    {
        nr_bytes = 0;
    }
#endif
    return nr_bytes;
}

static int socket_flush(php_stream *stream)
{
    return 0;
}

static int socket_close(php_stream *stream, int close_handle)
{
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return FAILURE;
    }
    /** set it null immediately */
    stream->abstract = nullptr;
    Socket *sock = (Socket*) abstract->socket;
    if (UNEXPECTED(!sock))
    {
        return FAILURE;
    }
    /**
     * it's always successful (even if the destructor rule is violated)
     * every calls passes through the hook function in PHP
     * so there is unnecessary to worry about the null pointer.
     */
    sock->close();
    delete sock;
    efree(abstract);
    return SUCCESS;
}

enum
{
    STREAM_XPORT_OP_BIND,
    STREAM_XPORT_OP_CONNECT,
    STREAM_XPORT_OP_LISTEN,
    STREAM_XPORT_OP_ACCEPT,
    STREAM_XPORT_OP_CONNECT_ASYNC,
    STREAM_XPORT_OP_GET_NAME,
    STREAM_XPORT_OP_GET_PEER_NAME,
    STREAM_XPORT_OP_RECV,
    STREAM_XPORT_OP_SEND,
    STREAM_XPORT_OP_SHUTDOWN,
};

enum
{
    STREAM_XPORT_CRYPTO_OP_SETUP, STREAM_XPORT_CRYPTO_OP_ENABLE
};

static int socket_cast(php_stream *stream, int castas, void **ret)
{
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return FAILURE;
    }
    Socket *sock = (Socket*) abstract->socket;
    if (UNEXPECTED(!sock))
    {
        return FAILURE;
    }

    switch (castas)
    {
    case PHP_STREAM_AS_STDIO:
        if (ret)
        {
            *(FILE**) ret = fdopen(sock->get_fd(), stream->mode);
            if (*ret)
            {
                return SUCCESS;
            }
            return FAILURE;
        }
        return SUCCESS;
    case PHP_STREAM_AS_FD_FOR_SELECT:
    case PHP_STREAM_AS_FD:
    case PHP_STREAM_AS_SOCKETD:
        if (ret)
            *(php_socket_t *) ret = sock->get_fd();
        return SUCCESS;
    default:
        return FAILURE;
    }
}

static int socket_stat(php_stream *stream, php_stream_statbuf *ssb)
{
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return FAILURE;
    }
    Socket *sock = (Socket*) abstract->socket;
    if (UNEXPECTED(!sock))
    {
        return FAILURE;
    }
    return zend_fstat(sock->get_fd(), &ssb->sb);
}

static inline int socket_connect(php_stream *stream, Socket *sock, php_stream_xport_param *xparam)
{
    char *host = nullptr, *bindto = nullptr;
    int portno = 0, bindport = 0;
    int ret = 0;
    zval *tmpzval = nullptr;
    char *ip_address = nullptr;

    if (UNEXPECTED(sock->get_fd() < 0))
    {
        return FAILURE;
    }

    if (sock->get_type() == SW_SOCK_TCP || sock->get_type() == SW_SOCK_TCP6 || sock->get_type() == SW_SOCK_UDP || sock->get_type() == SW_SOCK_UDP6)
    {
        ip_address = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext,
                &xparam->outputs.error_text);
        host = ip_address;
        if (sock->get_sock_type() == SOCK_STREAM)
        {
            int sockoptval = 1;
            setsockopt(sock->get_fd(), IPPROTO_TCP, TCP_NODELAY, (char*) &sockoptval, sizeof(sockoptval));
        }
    }
    else
    {
        host = xparam->inputs.name;
    }
    if (host == nullptr)
    {
        return FAILURE;
    }
    if (PHP_STREAM_CONTEXT(stream) && (tmpzval = php_stream_context_get_option(PHP_STREAM_CONTEXT(stream), "socket", "bindto")) != nullptr)
    {
        if (Z_TYPE_P(tmpzval) != IS_STRING)
        {
            if (xparam->want_errortext)
            {
                xparam->outputs.error_text = strpprintf(0, "local_addr context option is not a string.");
            }
            efree(ip_address);
            return FAILURE;
        }
        bindto = parse_ip_address_ex(Z_STRVAL_P(tmpzval), Z_STRLEN_P(tmpzval), &bindport, xparam->want_errortext, &xparam->outputs.error_text);
        if (bindto == nullptr)
        {
            efree(ip_address);
            return FAILURE;
        }
        if (!sock->bind(bindto, bindport))
        {
            efree(ip_address);
            efree(bindto);
            return FAILURE;
        }
    }
    
    if (xparam->inputs.timeout)
    {
        sock->set_timeout(xparam->inputs.timeout, SW_TIMEOUT_CONNECT);
    }
    if (sock->connect(host, portno) == false)
    {
        xparam->outputs.error_code = sock->errCode;
        if (sock->errMsg)
        {
            xparam->outputs.error_text = zend_string_init(sock->errMsg, strlen(sock->errMsg), 0);
        }
        ret = -1;
    }
    if (ip_address)
    {
        efree(ip_address);
    }
    if (bindto)
    {
        efree(bindto);
    }
    return ret;
}

static inline int socket_bind(php_stream *stream, Socket *sock, php_stream_xport_param *xparam STREAMS_DC)
{
    char *host = nullptr;
    int portno = 0;
    char *ip_address = nullptr;

    if (sock->get_type() == SW_SOCK_TCP || sock->get_type() == SW_SOCK_TCP6 || sock->get_type() == SW_SOCK_UDP || sock->get_type() == SW_SOCK_UDP6)
    {
        ip_address = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext, &xparam->outputs.error_text);
        host = ip_address;
    }
    else
    {
        host = xparam->inputs.name;
    }
    int ret = sock->bind(host, portno) ? 0 : -1;
    if (ip_address)
    {
        efree(ip_address);
    }
    return ret;
}

static inline int socket_accept(php_stream *stream, Socket *sock, php_stream_xport_param *xparam STREAMS_DC)
{
    int tcp_nodelay = 0;
    zval *tmpzval = nullptr;

    xparam->outputs.client = nullptr;

    if ((nullptr != PHP_STREAM_CONTEXT(stream))
            && (tmpzval = php_stream_context_get_option(PHP_STREAM_CONTEXT(stream), "socket", "tcp_nodelay")) != nullptr
            && zval_is_true(tmpzval))
    {
        tcp_nodelay = 1;
    }

    zend_string **textaddr = xparam->want_textaddr ? &xparam->outputs.textaddr : nullptr;
    struct sockaddr **addr = xparam->want_addr ? &xparam->outputs.addr : nullptr;
    socklen_t *addrlen = xparam->want_addr ? &xparam->outputs.addrlen : nullptr;

    struct timeval *timeout = xparam->inputs.timeout;
    zend_string **error_string = xparam->want_errortext ? &xparam->outputs.error_text : nullptr;
    int *error_code = &xparam->outputs.error_code;

    int error = 0;
    php_sockaddr_storage sa;
    socklen_t sl = sizeof(sa);

    if (timeout)
    {
        sock->set_timeout(timeout, SW_TIMEOUT_READ);
    }

    Socket *clisock = sock->accept();

#ifdef SW_USE_OPENSSL
    if (clisock != nullptr && clisock->open_ssl)
    {
        if (!clisock->ssl_handshake())
        {
            sock->errCode = clisock->errCode;
            delete clisock;
            clisock = nullptr;
        }
    }
#endif

    if (clisock == nullptr)
    {
        error = sock->errCode;
        if (error_code)
        {
            *error_code = error;
        }
        if (error_string)
        {
            *error_string = php_socket_error_str(error);
        }
        return FAILURE;
    }
    else
    {
        php_network_populate_name_from_sockaddr((struct sockaddr*) &sa, sl, textaddr, addr, addrlen);
#ifdef TCP_NODELAY
        if (tcp_nodelay)
        {
            setsockopt(clisock->get_fd(), IPPROTO_TCP, TCP_NODELAY, (char*) &tcp_nodelay, sizeof(tcp_nodelay));
        }
#endif
        php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t*) emalloc(sizeof(*abstract));
        memset(abstract, 0, sizeof(*abstract));

        abstract->socket = clisock;

        xparam->outputs.client = php_stream_alloc_rel(stream->ops, (void* )abstract, nullptr, "r+");
        if (xparam->outputs.client)
        {
            xparam->outputs.client->ctx = stream->ctx;
            if (stream->ctx)
            {
                GC_ADDREF(stream->ctx);
            }
        }
        return 0;
    }
}

static inline int socket_recvfrom(Socket *sock, char *buf, size_t buflen, zend_string **textaddr, struct sockaddr **addr,
        socklen_t *addrlen)
{
    int ret;
    int want_addr = textaddr || addr;

    if (want_addr)
    {
        php_sockaddr_storage sa;
        socklen_t sl = sizeof(sa);
        ret = sock->recvfrom(buf, buflen, (struct sockaddr*) &sa, &sl);
        if (sl)
        {
            php_network_populate_name_from_sockaddr((struct sockaddr*) &sa, sl, textaddr, addr, addrlen);
        }
        else
        {
            if (textaddr)
            {
                *textaddr = ZSTR_EMPTY_ALLOC();
            }
            if (addr)
            {
                *addr = nullptr;
                *addrlen = 0;
            }
        }
    }
    else
    {
        ret = sock->recv(buf, buflen);
    }

    return ret;
}

static inline int socket_sendto(Socket *sock, const char *buf, size_t buflen, struct sockaddr *addr, socklen_t addrlen)
{
    if (addr)
    {
        return sendto(sock->get_fd(), buf, buflen, 0, addr, addrlen);
    }
    else
    {
        return sock->send(buf, buflen);
    }
}

#ifdef SW_USE_OPENSSL

#define GET_VER_OPT(name)               (PHP_STREAM_CONTEXT(stream) && (val = php_stream_context_get_option(PHP_STREAM_CONTEXT(stream), "ssl", name)) != nullptr)
#define GET_VER_OPT_STRING(name, str)   if (GET_VER_OPT(name)) { convert_to_string_ex(val); str = Z_STRVAL_P(val); }
#define GET_VER_OPT_LONG(name, num)     if (GET_VER_OPT(name)) { convert_to_long_ex(val); num = Z_LVAL_P(val); }

static int socket_setup_crypto(php_stream *stream, Socket *sock, php_stream_xport_crypto_param *cparam STREAMS_DC)
{
    return 0;
}

static int socket_enable_crypto(php_stream *stream, Socket *sock, php_stream_xport_crypto_param *cparam STREAMS_DC)
{
    if (cparam->inputs.activate && !sock->is_ssl_enable())
    {
        return sock->ssl_handshake() ? 0 : -1;
    }
    else if (!cparam->inputs.activate && sock->is_ssl_enable())
    {
        return sock->ssl_shutdown() ? 0 : -1;
    }
    return -1;
}
#endif

static inline int socket_xport_api(php_stream *stream, Socket *sock, php_stream_xport_param *xparam STREAMS_DC)
{
    static const int shutdown_how[] = { SHUT_RD, SHUT_WR, SHUT_RDWR };

    switch (xparam->op)
    {
    case STREAM_XPORT_OP_LISTEN:
    {
        xparam->outputs.returncode = sock->listen(xparam->inputs.backlog) ? 0 : -1;
        break;
    }
    case STREAM_XPORT_OP_CONNECT:
    case STREAM_XPORT_OP_CONNECT_ASYNC:
        xparam->outputs.returncode = socket_connect(stream, sock, xparam);
        break;
    case STREAM_XPORT_OP_BIND:
    {
        if (sock->get_sock_domain() != AF_UNIX)
        {
            zval *tmpzval = nullptr;
            int sockoptval = 1;
            php_stream_context *ctx = PHP_STREAM_CONTEXT(stream);
            if (!ctx)
            {
                break;
            }

#ifdef SO_REUSEADDR
            setsockopt(sock->get_fd(), SOL_SOCKET, SO_REUSEADDR, (char*) &sockoptval, sizeof(sockoptval));
#endif

#ifdef SO_REUSEPORT
            if ((tmpzval = php_stream_context_get_option(ctx, "socket", "so_reuseport")) != nullptr
                    && zval_is_true(tmpzval))
            {
                setsockopt(sock->get_fd(), SOL_SOCKET, SO_REUSEPORT, (char*) &sockoptval, sizeof(sockoptval));
            }
#endif

#ifdef SO_BROADCAST
            if ((tmpzval = php_stream_context_get_option(ctx, "socket", "so_broadcast")) != nullptr
                    && zval_is_true(tmpzval))
            {
                setsockopt(sock->get_fd(), SOL_SOCKET, SO_BROADCAST, (char*) &sockoptval, sizeof(sockoptval));
            }
#endif
        }
        xparam->outputs.returncode = socket_bind(stream, sock, xparam STREAMS_CC);
        break;
    }
    case STREAM_XPORT_OP_ACCEPT:
        xparam->outputs.returncode = socket_accept(stream, sock, xparam STREAMS_CC);
        break;
    case STREAM_XPORT_OP_GET_NAME:
        xparam->outputs.returncode = php_network_get_sock_name(sock->get_fd(),
                xparam->want_textaddr ? &xparam->outputs.textaddr : nullptr,
                xparam->want_addr ? &xparam->outputs.addr : nullptr, xparam->want_addr ? &xparam->outputs.addrlen : nullptr
                );
        break;
    case STREAM_XPORT_OP_GET_PEER_NAME:
        xparam->outputs.returncode = php_network_get_peer_name(sock->get_fd(),
                xparam->want_textaddr ? &xparam->outputs.textaddr : nullptr,
                xparam->want_addr ? &xparam->outputs.addr : nullptr, xparam->want_addr ? &xparam->outputs.addrlen : nullptr
                );
        break;

    case STREAM_XPORT_OP_SEND:
        if ((xparam->inputs.flags & STREAM_OOB) == STREAM_OOB)
        {
            php_swoole_error(E_WARNING, "STREAM_OOB flags is not supports");
            xparam->outputs.returncode = -1;
            break;
        }
        xparam->outputs.returncode = socket_sendto(sock, xparam->inputs.buf, xparam->inputs.buflen, xparam->inputs.addr,
                xparam->inputs.addrlen);
        if (xparam->outputs.returncode == -1)
        {
            char *err = php_socket_strerror(php_socket_errno(), nullptr, 0);
            php_error_docref(nullptr, E_WARNING, "%s\n", err);
            efree(err);
        }
        break;

    case STREAM_XPORT_OP_RECV:
        if ((xparam->inputs.flags & STREAM_OOB) == STREAM_OOB)
        {
            php_swoole_error(E_WARNING, "STREAM_OOB flags is not supports");
            xparam->outputs.returncode = -1;
            break;
        }
        if ((xparam->inputs.flags & STREAM_PEEK) == STREAM_PEEK)
        {
            xparam->outputs.returncode = sock->peek(xparam->inputs.buf, xparam->inputs.buflen);
        }
        else
        {
            xparam->outputs.returncode = socket_recvfrom(sock, xparam->inputs.buf, xparam->inputs.buflen,
                    xparam->want_textaddr ? &xparam->outputs.textaddr : nullptr,
                    xparam->want_addr ? &xparam->outputs.addr : nullptr,
                    xparam->want_addr ? &xparam->outputs.addrlen : nullptr
                    );
        }
        break;
    case STREAM_XPORT_OP_SHUTDOWN:
        xparam->outputs.returncode = sock->shutdown(shutdown_how[xparam->how]);
        break;
    default:
#ifdef SW_DEBUG
        php_swoole_fatal_error(E_WARNING, "socket_xport_api: unsupported option %d", xparam->op);
#endif
        break;
    }
    return PHP_STREAM_OPTION_RETURN_OK;
}

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract || !abstract->socket))
    {
        return PHP_STREAM_OPTION_RETURN_ERR;
    }
    Socket *sock = (Socket*) abstract->socket;
    switch (option)
    {
    case PHP_STREAM_OPTION_BLOCKING:
        // The coroutine socket always consistent with the sync blocking socket
        return value ? PHP_STREAM_OPTION_RETURN_OK : PHP_STREAM_OPTION_RETURN_ERR;
    case PHP_STREAM_OPTION_XPORT_API:
    {
        return socket_xport_api(stream, sock, (php_stream_xport_param *) ptrparam STREAMS_CC);
    }
    case PHP_STREAM_OPTION_META_DATA_API:
    {
#ifdef SW_USE_OPENSSL
        SSL *ssl = sock->socket ? sock->socket->ssl : nullptr;
        if (ssl)
        {
            zval tmp;
            const char *proto_str;
            const SSL_CIPHER *cipher;

            array_init(&tmp);
            switch (SSL_version(ssl))
            {
#ifdef HAVE_TLS13
            case TLS1_3_VERSION:
                proto_str = "TLSv1.3";
                break;
#endif
#ifdef HAVE_TLS12
            case TLS1_2_VERSION:
                proto_str = "TLSv1.2";
                break;
#endif
#ifdef HAVE_TLS11
            case TLS1_1_VERSION:
                proto_str = "TLSv1.1";
                break;
#endif
            case TLS1_VERSION:
                proto_str = "TLSv1";
                break;
#ifdef HAVE_SSL3
            case SSL3_VERSION:
                proto_str = "SSLv3";
            break;
#endif
            default:
                proto_str = "UNKNOWN";
                break;
            }

            cipher = SSL_get_current_cipher(ssl);
            add_assoc_string(&tmp, "protocol", (char* )proto_str);
            add_assoc_string(&tmp, "cipher_name", (char * ) SSL_CIPHER_get_name(cipher));
            add_assoc_long(&tmp, "cipher_bits", SSL_CIPHER_get_bits(cipher, nullptr));
            add_assoc_string(&tmp, "cipher_version", (char *) SSL_CIPHER_get_version(cipher));
            add_assoc_zval((zval *)ptrparam, "crypto", &tmp);
        }
#endif
        add_assoc_bool((zval *)ptrparam, "timed_out", sock->errCode == ETIMEDOUT);
        add_assoc_bool((zval *)ptrparam, "eof", stream->eof);
        add_assoc_bool((zval *)ptrparam, "blocked", 1);
        break;
    }
    case PHP_STREAM_OPTION_READ_TIMEOUT:
    {
        abstract->socket->set_timeout((struct timeval*) ptrparam, SW_TIMEOUT_READ);
        break;
    }
#ifdef SW_USE_OPENSSL
    case PHP_STREAM_OPTION_CRYPTO_API:
    {
        php_stream_xport_crypto_param *cparam = (php_stream_xport_crypto_param *) ptrparam;
        switch (cparam->op)
        {
        case STREAM_XPORT_CRYPTO_OP_SETUP:
            cparam->outputs.returncode = socket_setup_crypto(stream, sock, cparam STREAMS_CC);
            return PHP_STREAM_OPTION_RETURN_OK;
        case STREAM_XPORT_CRYPTO_OP_ENABLE:
            cparam->outputs.returncode = socket_enable_crypto(stream, sock, cparam STREAMS_CC);
            return PHP_STREAM_OPTION_RETURN_OK;
        default:
            /* never here */
            SW_ASSERT(0);
            break;
        }
        break;
    }
#endif
    case PHP_STREAM_OPTION_CHECK_LIVENESS:
    {
        return sock->check_liveness() ? PHP_STREAM_OPTION_RETURN_OK : PHP_STREAM_OPTION_RETURN_ERR;
    }
    case PHP_STREAM_OPTION_READ_BUFFER:
    case PHP_STREAM_OPTION_WRITE_BUFFER:
    {
        // TODO: read/write buffer
        break;
    }
    default:
#ifdef SW_DEBUG
        php_swoole_fatal_error(E_WARNING, "socket_set_option: unsupported option %d with value %d", option, value);
#endif
        break;
    }
    return PHP_STREAM_OPTION_RETURN_OK;
}

static php_stream *socket_create(
    const char *proto, size_t protolen, const char *resourcename, size_t resourcenamelen,
    const char *persistent_id, int options, int flags, struct timeval *timeout, php_stream_context *context
    STREAMS_DC
)
{
    php_stream *stream = nullptr;
    php_swoole_netstream_data_t *abstract = nullptr;
    Socket *sock;

    Coroutine::get_current_safe();

    if (SW_STREQ(proto, protolen, "tcp"))
    {
        _tcp:
        sock = new Socket(resourcename[0] == '[' ? SW_SOCK_TCP6 : SW_SOCK_TCP);
    }
    else if (SW_STREQ(proto, protolen, "ssl") || SW_STREQ(proto, protolen, "tls"))
    {
#ifdef SW_USE_OPENSSL
        sock = new Socket(resourcename[0] == '[' ? SW_SOCK_TCP6 : SW_SOCK_TCP);
        sock->open_ssl = true;
#else
        php_swoole_error(E_WARNING, "you must configure with `--enable-openssl` to support ssl connection when compiling Swoole");
        return nullptr;
#endif
    }
    else if (SW_STREQ(proto, protolen, "unix"))
    {
        sock = new Socket(SW_SOCK_UNIX_STREAM);
    }
    else if (SW_STREQ(proto, protolen, "udp"))
    {
        sock = new Socket(SW_SOCK_UDP);
    }
    else if (SW_STREQ(proto, protolen, "udg"))
    {
        sock = new Socket(SW_SOCK_UNIX_DGRAM);
    }
    else
    {
        /* abort? */
        goto _tcp;
    }

    if (UNEXPECTED(sock->get_fd() < 0))
    {
        _failed:
        if (!stream)
        {
            delete sock;
        }
        else
        {
            php_stream_close(stream);
        }
        return nullptr;
    }

    sock->set_zero_copy(true);

    abstract = (php_swoole_netstream_data_t*) ecalloc(1, sizeof(*abstract));
    abstract->socket = sock;
    abstract->stream.socket = sock->get_fd();

    if (timeout)
    {
        sock->set_timeout(timeout);
        abstract->stream.timeout = *timeout;
    }
    else if (FG(default_socket_timeout) > 0)
    {
        sock->set_timeout((double) FG(default_socket_timeout));
        abstract->stream.timeout.tv_sec = FG(default_socket_timeout);
    }
    else
    {
        sock->set_timeout(-1);
        abstract->stream.timeout.tv_sec = -1;
    }

    persistent_id = nullptr;//prevent stream api in user level using pconnect to persist the socket
    stream = php_stream_alloc_rel(&socket_ops, abstract, persistent_id, "r+");

    if (stream == nullptr)
    {
        goto _failed;
    }

    if (context && ZVAL_IS_ARRAY(&context->options))
    {
#ifdef SW_USE_OPENSSL
        zval *ztmp;
        if (sock->open_ssl && php_swoole_array_get_value(Z_ARRVAL_P(&context->options), "ssl", ztmp) && ZVAL_IS_ARRAY(ztmp))
        {
            [](Socket *sock, HashTable *options)
            {
                zval zalias, *ztmp;
                array_init(&zalias);
#define SSL_OPTION_ALIAS(name, alias) do { \
    if (php_swoole_array_get_value(options, name, ztmp)) \
    { \
        add_assoc_zval_ex(&zalias, ZEND_STRL(alias), ztmp); \
    } \
} while (0);
                SSL_OPTION_ALIAS("peer_name", "ssl_host_name");
                SSL_OPTION_ALIAS("verify_peer", "ssl_verify_peer");
                SSL_OPTION_ALIAS("allow_self_signed", "ssl_allow_self_signed");
                SSL_OPTION_ALIAS("cafile", "ssl_cafile");
                SSL_OPTION_ALIAS("capath", "ssl_capath");
                SSL_OPTION_ALIAS("local_cert", "ssl_cert_file");
                SSL_OPTION_ALIAS("local_pk", "ssl_key_file");
                SSL_OPTION_ALIAS("passphrase", "ssl_passphrase");
                SSL_OPTION_ALIAS("verify_depth", "ssl_verify_depth");
                SSL_OPTION_ALIAS("disable_compression", "ssl_disable_compression");
#undef SSL_OPTION_ALIAS
                php_swoole_socket_set_ssl(sock, &zalias);
                zend_array_destroy(Z_ARRVAL(zalias));
            } (sock, Z_ARRVAL_P(ztmp));
        }
#endif
    }

    return stream;
}

bool PHPCoroutine::enable_hook(int flags)
{
    if (!hook_init)
    {
        HashTable *xport_hash = php_stream_xport_get_hash();
        // php_stream
        ori_factory.tcp = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("tcp"));
        ori_factory.udp = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udp"));
        ori_factory._unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("unix"));
        ori_factory.udg = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udg"));
        ori_factory.ssl = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("ssl"));
        ori_factory.tls = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("tls"));

        // file
        memcpy((void*) &ori_php_plain_files_wrapper, &php_plain_files_wrapper, sizeof(php_plain_files_wrapper));

        function_table = (zend_array*) emalloc(sizeof(zend_array));
        zend_hash_init(function_table, 8, nullptr, nullptr, 0);

        hook_init = true;
    }
    // php_stream
    if (flags & SW_HOOK_TCP)
    {
        if (!(hook_flags & SW_HOOK_TCP))
        {
            if (php_stream_xport_register("tcp", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_TCP;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_TCP)
        {
            php_stream_xport_register("tcp", ori_factory.tcp);
        }
    }
    if (flags & SW_HOOK_UDP)
    {
        if (!(hook_flags & SW_HOOK_UDP))
        {
            if (php_stream_xport_register("udp", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_UDP;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_UDP)
        {
            php_stream_xport_register("udp", ori_factory.udp);
        }
    }
    if (flags & SW_HOOK_UNIX)
    {
        if (!(hook_flags & SW_HOOK_UNIX))
        {
            if (php_stream_xport_register("unix", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_UNIX;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_UNIX)
        {
            php_stream_xport_register("unix", ori_factory._unix);
        }
    }
    if (flags & SW_HOOK_UDG)
    {
        if (!(hook_flags & SW_HOOK_UDG))
        {
            if (php_stream_xport_register("udg", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_UDG;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_UDG)
        {
            php_stream_xport_register("udg", ori_factory.udg);
        }
    }
    if (flags & SW_HOOK_SSL)
    {
        if (!(hook_flags & SW_HOOK_SSL))
        {
            if (php_stream_xport_register("ssl", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_SSL;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_SSL)
        {
            if (ori_factory.ssl != nullptr) {
                php_stream_xport_register("ssl", ori_factory.ssl);
            } else {
                php_stream_xport_unregister("ssl");
            }
        }
    }
    if (flags & SW_HOOK_TLS)
    {
        if (!(hook_flags & SW_HOOK_TLS))
        {
            if (php_stream_xport_register("tls", socket_create) != SUCCESS)
            {
                flags ^= SW_HOOK_TLS;
            }
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_TLS)
        {
            if (ori_factory.tls != nullptr)
            {
                php_stream_xport_register("tls", ori_factory.tls);
            }
            else
            {
                php_stream_xport_unregister("tls");
            }
        }
    }
    if (flags & SW_HOOK_STREAM_FUNCTION)
    {
        if (!(hook_flags & SW_HOOK_STREAM_FUNCTION))
        {
            SW_HOOK_FUNC(stream_select);
            SW_HOOK_FUNC(stream_socket_pair);
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_STREAM_FUNCTION)
        {
            SW_UNHOOK_FUNC(stream_select);
            SW_UNHOOK_FUNC(stream_socket_pair);
        }
    }
    // file
    if (flags & SW_HOOK_FILE)
    {
        if (!(hook_flags & SW_HOOK_FILE))
        {
            memcpy((void*) &php_plain_files_wrapper, &sw_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_FILE)
        {
            memcpy((void*) &php_plain_files_wrapper, &ori_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
        }
    }
    // sleep
    if (flags & SW_HOOK_SLEEP)
    {
        if (!(hook_flags & SW_HOOK_SLEEP))
        {
            SW_HOOK_FUNC(sleep);
            SW_HOOK_FUNC(usleep);
            SW_HOOK_FUNC(time_nanosleep);
            SW_HOOK_FUNC(time_sleep_until);
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_SLEEP)
        {
            SW_UNHOOK_FUNC(sleep);
            SW_UNHOOK_FUNC(usleep);
            SW_UNHOOK_FUNC(time_nanosleep);
            SW_UNHOOK_FUNC(time_sleep_until);
        }
    }
    // proc_open
    if (flags & SW_HOOK_PROC)
    {
        if (!(hook_flags & SW_HOOK_PROC))
        {
            SW_HOOK_FUNC(proc_open);
            SW_HOOK_FUNC(proc_close);
            SW_HOOK_FUNC(proc_get_status);
            SW_HOOK_FUNC(proc_terminate);
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_PROC)
        {
            SW_UNHOOK_FUNC(proc_open);
            SW_UNHOOK_FUNC(proc_close);
            SW_UNHOOK_FUNC(proc_get_status);
            SW_UNHOOK_FUNC(proc_terminate);
        }
    }
    // blocking function
    if (flags & SW_HOOK_BLOCKING_FUNCTION)
    {
        if (!(hook_flags & SW_HOOK_BLOCKING_FUNCTION))
        {
            hook_func(ZEND_STRL("gethostbyname"), PHP_FN(swoole_coroutine_gethostbyname));
            hook_func(ZEND_STRL("exec"));
            hook_func(ZEND_STRL("shell_exec"));
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_BLOCKING_FUNCTION)
        {
            SW_UNHOOK_FUNC(gethostbyname);
            SW_UNHOOK_FUNC(exec);
            SW_UNHOOK_FUNC(shell_exec);
        }
    }

    if (flags & SW_HOOK_CURL)
    {
        if (!(hook_flags & SW_HOOK_CURL))
        {
            hook_func(ZEND_STRL("curl_init"));
            hook_func(ZEND_STRL("curl_setopt"));
            hook_func(ZEND_STRL("curl_setopt_array"));
            hook_func(ZEND_STRL("curl_exec"));
            hook_func(ZEND_STRL("curl_getinfo"));
            hook_func(ZEND_STRL("curl_errno"));
            hook_func(ZEND_STRL("curl_error"));
            hook_func(ZEND_STRL("curl_reset"));
            hook_func(ZEND_STRL("curl_close"));
            hook_func(ZEND_STRL("curl_multi_getcontent"));
        }
    }
    else
    {
        if (hook_flags & SW_HOOK_CURL)
        {
            SW_UNHOOK_FUNC(curl_init);
            SW_UNHOOK_FUNC(curl_setopt);
            SW_UNHOOK_FUNC(curl_setopt_array);
            SW_UNHOOK_FUNC(curl_exec);
            SW_UNHOOK_FUNC(curl_getinfo);
            SW_UNHOOK_FUNC(curl_errno);
            SW_UNHOOK_FUNC(curl_error);
            SW_UNHOOK_FUNC(curl_reset);
            SW_UNHOOK_FUNC(curl_close);
            SW_UNHOOK_FUNC(curl_multi_getcontent);
        }
    }

    hook_flags = flags;
    return true;
}

bool PHPCoroutine::disable_hook()
{
    return enable_hook(0);
}

static PHP_METHOD(swoole_runtime, enableCoroutine)
{
    zval *zflags = nullptr;
    /*TODO:[v4.6] enable SW_HOOK_CURL by default after curl handler completed */
    zend_long flags = SW_HOOK_ALL;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(zflags) // or zenable
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zflags)
    {
        if (Z_TYPE_P(zflags) == IS_LONG)
        {
            flags = SW_MAX(0, Z_LVAL_P(zflags));
        }
        else if (ZVAL_IS_BOOL(zflags))
        {
            if (!Z_BVAL_P(zflags))
            {
                flags = 0;
            }
        }
        else
        {
            const char *space, *class_name = get_active_class_name(&space);
            zend_type_error("%s%s%s() expects parameter %d to be %s, %s given", class_name, space, get_active_function_name(), 1, "bool or long", zend_zval_type_name(zflags));
        }
    }

    RETURN_BOOL(PHPCoroutine::enable_hook(flags));
}

static PHP_METHOD(swoole_runtime, getHookFlags)
{
    RETURN_LONG(hook_flags);
}

static PHP_METHOD(swoole_runtime, setHookFlags)
{
    zend_long flags = SW_HOOK_ALL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(PHPCoroutine::enable_hook(flags));
}

static PHP_FUNCTION(swoole_sleep)
{
    zend_long num;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &num) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (num < 0)
    {
        php_error_docref(nullptr, E_WARNING, "Number of seconds must be greater than or equal to 0");
        RETURN_FALSE;
    }

    if (num >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        RETURN_LONG(System::sleep((double ) num) < 0 ? num : 0);
    }
    else
    {
        RETURN_LONG(php_sleep(num));
    }
}

static PHP_FUNCTION(swoole_usleep)
{
    zend_long num;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &num) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (num < 0)
    {
        php_error_docref(nullptr, E_WARNING, "Number of seconds must be greater than or equal to 0");
        RETURN_FALSE;
    }
    double sec = (double) num / 1000000;
    if (sec >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        System::sleep(sec);
    }
    else
    {
        usleep((unsigned int)num);
    }
}

static PHP_FUNCTION(swoole_time_nanosleep)
{
    zend_long tv_sec, tv_nsec;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &tv_sec, &tv_nsec) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (tv_sec < 0)
    {
        php_error_docref(nullptr, E_WARNING, "The seconds value must be greater than 0");
        RETURN_FALSE;
    }
    if (tv_nsec < 0)
    {
        php_error_docref(nullptr, E_WARNING, "The nanoseconds value must be greater than 0");
        RETURN_FALSE;
    }
    double _time = (double) tv_sec + (double) tv_nsec / 1000000000.00;
    if (_time >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        System::sleep(_time);
    }
    else
    {
        struct timespec php_req, php_rem;
        php_req.tv_sec = (time_t) tv_sec;
        php_req.tv_nsec = (long) tv_nsec;

        if (nanosleep(&php_req, &php_rem) == 0)
        {
            RETURN_TRUE;
        }
        else if (errno == EINTR)
        {
            array_init(return_value);
            add_assoc_long_ex(return_value, "seconds", sizeof("seconds") - 1, php_rem.tv_sec);
            add_assoc_long_ex(return_value, "nanoseconds", sizeof("nanoseconds") - 1, php_rem.tv_nsec);
        }
        else if (errno == EINVAL)
        {
            php_swoole_error(E_WARNING, "nanoseconds was not in the range 0 to 999 999 999 or seconds was negative");
        }
    }
}

static PHP_FUNCTION(swoole_time_sleep_until)
{
    double d_ts, c_ts;
    struct timeval tm;
    struct timespec php_req, php_rem;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &d_ts) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (gettimeofday((struct timeval *) &tm, nullptr) != 0)
    {
        RETURN_FALSE;
    }

    c_ts = (double) (d_ts - tm.tv_sec - tm.tv_usec / 1000000.00);
    if (c_ts < 0)
    {
        php_error_docref(nullptr, E_WARNING, "Sleep until to time is less than current time");
        RETURN_FALSE;
    }

    php_req.tv_sec = (time_t) c_ts;
    if (php_req.tv_sec > c_ts)
    {
        php_req.tv_sec--;
    }
    php_req.tv_nsec = (long) ((c_ts - php_req.tv_sec) * 1000000000.00);

    double _time = (double) php_req.tv_sec + (double) php_req.tv_nsec / 1000000000.00;
    if (_time >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        System::sleep(_time);
    }
    else
    {
        while (nanosleep(&php_req, &php_rem))
        {
            if (errno == EINTR)
            {
                php_req.tv_sec = php_rem.tv_sec;
                php_req.tv_nsec = php_rem.tv_nsec;
            }
            else
            {
                RETURN_FALSE;
            }
        }
    }
    RETURN_TRUE;
}

static void stream_array_to_fd_set(zval *stream_array, std::unordered_map<int, socket_poll_fd> &fds, int event)
{
    zval *elem;
    zend_ulong index;
    zend_string *key;
    php_socket_t sock;

    if (!ZVAL_IS_ARRAY(stream_array))
    {
        return;
    }

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(stream_array), index, key, elem)
    {
        ZVAL_DEREF(elem);
        sock = swoole_convert_to_fd(elem);
        if (sock < 0)
        {
            continue;
        }
        auto i = fds.find(sock);
        if (i == fds.end())
        {
            fds.emplace(make_pair(sock, socket_poll_fd(event, new zend::key_value(index, key, elem))));
        }
        else
        {
            i->second.events |= event;
        }
    }
    ZEND_HASH_FOREACH_END();
}

static int stream_array_emulate_read_fd_set(zval *stream_array)
{
    zval *elem, *dest_elem, new_array;
    HashTable *ht;
    php_stream *stream;
    int ret = 0;
    zend_ulong num_ind;
    zend_string *key;

    if (!ZVAL_IS_ARRAY(stream_array))
    {
        return 0;
    }

    ZVAL_NEW_ARR(&new_array);
    ht = Z_ARRVAL(new_array);
    zend_hash_init(ht, zend_hash_num_elements(Z_ARRVAL_P(stream_array)), nullptr, ZVAL_PTR_DTOR, 0);

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(stream_array), num_ind, key, elem)
    {
        ZVAL_DEREF(elem);
        php_stream_from_zval_no_verify(stream, elem);
        if (stream == nullptr)
        {
            continue;
        }
        if ((stream->writepos - stream->readpos) > 0)
        {
            /* allow readable non-descriptor based streams to participate in stream_select.
             * Non-descriptor streams will only "work" if they have previously buffered the
             * data.  Not ideal, but better than nothing.
             * This branch of code also allows blocking streams with buffered data to
             * operate correctly in stream_select.
             * */
            dest_elem = !key ? zend_hash_index_update(ht, num_ind, elem) : zend_hash_update(ht, key, elem);
            zval_add_ref(dest_elem);
            ret++;
            continue;
        }
    } ZEND_HASH_FOREACH_END();

    if (ret > 0)
    {
        /* destroy old array and add new one */
        zend_array_destroy(Z_ARR_P(stream_array));
        ZVAL_ARR(stream_array, ht);
    }
    else
    {
        zend_array_destroy(ht);
    }

    return ret;
}

static PHP_FUNCTION(swoole_stream_select)
{
    Coroutine::get_current_safe();

    zval *r_array, *w_array, *e_array;
    zend_long sec, usec = 0;
    zend_bool secnull;
    int retval = 0;

    ZEND_PARSE_PARAMETERS_START(4, 5)
        Z_PARAM_ARRAY_EX(r_array, 1, 1)
        Z_PARAM_ARRAY_EX(w_array, 1, 1)
        Z_PARAM_ARRAY_EX(e_array, 1, 1)
        Z_PARAM_LONG_EX(sec, secnull, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(usec)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    std::unordered_map<int, socket_poll_fd> fds;

    if (r_array != nullptr)
    {
        stream_array_to_fd_set(r_array, fds, SW_EVENT_READ);
    }

    if (w_array != nullptr)
    {
        stream_array_to_fd_set(w_array, fds, SW_EVENT_WRITE);
    }

    if (e_array != nullptr)
    {
        stream_array_to_fd_set(e_array, fds, SW_EVENT_ERROR);
    }

    if (fds.size() == 0)
    {
        php_error_docref(nullptr, E_WARNING, "No stream arrays were passed");
        RETURN_FALSE;
    }

    double timeout = -1;
    if (!secnull)
    {
        if (sec < 0)
        {
            php_error_docref(nullptr, E_WARNING, "The seconds parameter must be greater than 0");
            RETURN_FALSE;
        }
        else if (usec < 0)
        {
            php_error_docref(nullptr, E_WARNING, "The microseconds parameter must be greater than 0");
            RETURN_FALSE;
        }
        timeout = (double) sec + ((double) usec / 1000000);
    }

    /* slight hack to support buffered data; if there is data sitting in the
     * read buffer of any of the streams in the read array, let's pretend
     * that we selected, but return only the readable sockets */
    if (r_array != nullptr)
    {
        retval = stream_array_emulate_read_fd_set(r_array);
        if (retval > 0)
        {
            if (w_array != nullptr)
            {
                zend_hash_clean(Z_ARRVAL_P(w_array));
            }
            if (e_array != nullptr)
            {
                zend_hash_clean(Z_ARRVAL_P(e_array));
            }
            RETURN_LONG(retval);
        }
    }

    /**
     * timeout or add failed
     */
    if (!System::socket_poll(fds, timeout))
    {
        RETURN_LONG(0);
    }

    if (r_array != nullptr)
    {
        zend_hash_clean(Z_ARRVAL_P(r_array));
    }
    if (w_array != nullptr)
    {
        zend_hash_clean(Z_ARRVAL_P(w_array));
    }
    if (e_array != nullptr)
    {
        zend_hash_clean(Z_ARRVAL_P(e_array));
    }

    for (auto &i : fds)
    {
        zend::key_value *kv = (zend::key_value *) i.second.ptr;
        int revents = i.second.revents;
        SW_ASSERT((revents & (~(SW_EVENT_READ |SW_EVENT_WRITE | SW_EVENT_ERROR))) == 0);
        if (revents > 0)
        {
            if ((revents & SW_EVENT_READ) && r_array)
            {
                kv->add_to(r_array);
            }
            if ((revents & SW_EVENT_WRITE) && w_array)
            {
                kv->add_to(w_array);
            }
            if ((revents & SW_EVENT_ERROR) && e_array)
            {
                kv->add_to(e_array);
            }
            retval++;
        }
        delete kv;
    }

    RETURN_LONG(retval);
}

static void hook_func(const char *name, size_t l_name, zif_handler handler)
{
    real_func *rf = (real_func *) zend_hash_str_find_ptr(function_table, name, l_name);
    bool use_php_func = false;
    /**
     * use php library function
     */
    if (handler == nullptr)
    {
        handler = PHP_FN(swoole_user_func_handler);
        use_php_func = true;
    }
    if (rf)
    {
        rf->function->internal_function.handler = handler;
        return;
    }

    zend_function *zf = (zend_function *) zend_hash_str_find_ptr(EG(function_table), name, l_name);
    if (zf == nullptr)
    {
        return;
    }

    rf = (real_func *) emalloc(sizeof(real_func));
    bzero(rf, sizeof(real_func));
    rf->function = zf;
    rf->ori_handler = zf->internal_function.handler;
    zf->internal_function.handler = handler;

    if (use_php_func)
    {
        char func[128];
        memcpy(func, ZEND_STRL("swoole_"));
        memcpy(func + 7, zf->common.function_name->val, zf->common.function_name->len);

        ZVAL_STRINGL(&rf->name, func, zf->common.function_name->len + 7);

        char *func_name;
        zend_fcall_info_cache *func_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
        if (!sw_zend_is_callable_ex(&rf->name, nullptr, 0, &func_name, nullptr, func_cache, nullptr))
        {
            php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
            return;
        }
        efree(func_name);
        rf->fci_cache = func_cache;
    }

    zend_hash_add_ptr(function_table, zf->common.function_name, rf);
}

static void unhook_func(const char *name, size_t l_name)
{
    real_func *rf = (real_func *) zend_hash_str_find_ptr(function_table, name, l_name);
    if (rf == nullptr)
    {
        return;
    }
    rf->function->internal_function.handler = rf->ori_handler;
}

php_stream *php_swoole_create_stream_from_socket(php_socket_t _fd, int domain, int type, int protocol STREAMS_DC)
{
    Socket *sock = new Socket(_fd, domain, type, protocol);

    if (FG(default_socket_timeout) > 0)
    {
        sock->set_timeout((double) FG(default_socket_timeout));
    }

    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t*) ecalloc(1, sizeof(*abstract));

    abstract->socket = sock;
    abstract->stream.timeout.tv_sec = FG(default_socket_timeout);
    abstract->stream.socket = sock->get_fd();

    php_stream *stream = php_stream_alloc_rel(&socket_ops, abstract, nullptr, "r+");

    if (stream == nullptr)
    {
        delete sock;
    }
    else
    {
        stream->flags |= PHP_STREAM_FLAG_AVOID_BLOCKING;
    }

    return stream;
}

static PHP_FUNCTION(swoole_stream_socket_pair)
{
    zend_long domain, type, protocol;
    php_stream *s1, *s2;
    php_socket_t pair[2];

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(domain)
        Z_PARAM_LONG(type)
        Z_PARAM_LONG(protocol)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (0 != socketpair((int) domain, (int) type, (int) protocol, pair))
    {
        php_swoole_error(E_WARNING, "failed to create sockets: [%d]: %s", errno, strerror(errno));
        RETURN_FALSE;
    }

    array_init(return_value);

    php_swoole_check_reactor();

    s1 = php_swoole_create_stream_from_socket(pair[0], domain, type, protocol STREAMS_CC);
    s2 = php_swoole_create_stream_from_socket(pair[1], domain, type, protocol STREAMS_CC);

    /* set the __exposed flag.
     * php_stream_to_zval() does, add_next_index_resource() does not */
    php_stream_auto_cleanup(s1);
    php_stream_auto_cleanup(s2);

    add_next_index_resource(return_value, s1->res);
    add_next_index_resource(return_value, s2->res);
}

static PHP_FUNCTION(swoole_user_func_handler)
{
    zend_fcall_info fci;
    fci.size = sizeof(fci);
    fci.object = nullptr;
    fci.function_name = {};
    fci.retval = return_value;
    fci.param_count = ZEND_NUM_ARGS();
    fci.params = ZEND_CALL_ARG(execute_data, 1);
    fci.no_separation = 1;

    real_func *rf = (real_func *) zend_hash_find_ptr(function_table, execute_data->func->common.function_name);
    zend_call_function(&fci, rf->fci_cache);
}
