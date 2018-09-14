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
#include "php_swoole.h"
#include "swoole_coroutine.h"
#include "socket.h"

#include <unordered_map>
#include <initializer_list>

enum hook_type
{
    SW_HOOK_FILE = 1u << 1,
    SW_HOOK_SLEEP = 1u << 2,
    SW_HOOK_TCP = 1u << 3,
    SW_HOOK_UDP = 1u << 4,
    SW_HOOK_UNIX = 1u << 5,
    SW_HOOK_UDG = 1u << 6,
    SW_HOOK_SSL = 1u << 7,
    SW_HOOK_TLS = 1u << 8,
    SW_HOOK_ALL = 0x7fffffff,
};

using namespace swoole;
using namespace std;

extern "C"
{
static PHP_METHOD(swoole_runtime, enableStrictMode);
static PHP_METHOD(swoole_runtime, enableCoroutine);
static PHP_FUNCTION(_sleep);
static PHP_FUNCTION(_usleep);
static PHP_FUNCTION(_time_nanosleep);
static PHP_FUNCTION(_time_sleep_until);
}

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam);
static size_t socket_read(php_stream *stream, char *buf, size_t count);
static size_t socket_write(php_stream *stream, const char *buf, size_t count);
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

static zend_class_entry *ce;
static php_stream_ops socket_ops
{
    socket_write,
    socket_read,
    socket_close,
    socket_flush,
    "tcp_socket/coroutine",
    NULL, /* seek */
    socket_cast,
    socket_stat,
    socket_set_option,
};
static bool hook_init = false;
static int hook_flags;

static struct
{
    php_stream_transport_factory tcp;
    php_stream_transport_factory udp;
    php_stream_transport_factory unix;
    php_stream_transport_factory udg;
#ifdef SW_USE_OPENSSL
    php_stream_transport_factory ssl;
    php_stream_transport_factory tls;
#endif
} ori_factory =
{ nullptr, nullptr, nullptr, nullptr,
#ifdef SW_USE_OPENSSL
        nullptr,
#endif
        };

static php_stream_wrapper ori_php_plain_files_wrapper;
static php_stream_ops ori_php_stream_stdio_ops;

static zend_function *ori_sleep;
static zend_function *ori_usleep;
static zend_function *ori_time_nanosleep;
static zend_function *ori_time_sleep_until;

extern "C"
{
#include "ext/standard/file.h"
#include "thirdparty/plain_wrapper.c"
}

static const zend_function_entry swoole_runtime_methods[] =
{
    PHP_ME(swoole_runtime, enableStrictMode, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_runtime, enableCoroutine, arginfo_swoole_runtime_enableCoroutine, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_runtime_init(int module_number TSRMLS_DC)
{
    static zend_class_entry _ce;
    INIT_CLASS_ENTRY(_ce, "Swoole\\Runtime", swoole_runtime_methods);
    ce = zend_register_internal_class(&_ce TSRMLS_CC);
}

static auto block_io_functions =
{ "sleep", "usleep", "time_nanosleep", "time_sleep_until", "file_get_contents", "curl_init", "stream_select",
        "socket_select", "gethostbyname", };

static auto block_io_classes =
{ "redis", "mysqli", };

static PHP_METHOD(swoole_runtime, enableStrictMode)
{
    for (auto f : block_io_functions)
    {
        zend_disable_function((char *) f, strlen((char *) f));
    }
    for (auto c : block_io_classes)
    {
        zend_disable_class((char *) c, strlen((char *) c));
    }
}

static inline char *parse_ip_address_ex(const char *str, size_t str_len, int *portno, int get_err, zend_string **err)
{
    char *colon;
    char *host = NULL;

#ifdef HAVE_IPV6
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
            return NULL;
        }
        *portno = atoi(p + 2);
        return estrndup(str + 1, p - str - 1);
    }
#endif
    if (str_len)
    {
        colon = (char*) memchr(str, ':', str_len - 1);
    }
    else
    {
        colon = NULL;
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
        return NULL;
    }

    return host;
}

static size_t socket_write(php_stream *stream, const char *buf, size_t count)
{
    Socket *sock = (Socket*) stream->abstract;
    int didwrite;
    if (!sock)
    {
        return 0;
    }

    didwrite = sock->send_all(buf, count);
    if (didwrite <= 0)
    {
        int err = sock->errCode;
        char *estr;

        estr = php_socket_strerror(err, NULL, 0);
        php_error_docref(NULL, E_NOTICE, "send of " ZEND_LONG_FMT " bytes failed with errno=%d %s", (zend_long) count,
                err, estr);
        efree(estr);
    }

    if (didwrite > 0)
    {
        php_stream_notify_progress_increment(PHP_STREAM_CONTEXT(stream), didwrite, 0);
    }

    if (didwrite < 0)
    {
        didwrite = 0;
    }

    return didwrite;
}

static size_t socket_read(php_stream *stream, char *buf, size_t count)
{
    Socket *sock = (Socket*) stream->abstract;
    ssize_t nr_bytes = 0;

    if (!sock)
    {
        return 0;
    }

    nr_bytes = sock->recv(buf, count);
    stream->eof = (nr_bytes == 0 || nr_bytes == -1);

    if (nr_bytes > 0)
    {
        php_stream_notify_progress_increment(PHP_STREAM_CONTEXT(stream), nr_bytes, 0);
    }

    if (nr_bytes < 0)
    {
        nr_bytes = 0;
    }

    return nr_bytes;
}

static int socket_flush(php_stream *stream)
{
    return 0;
}

static int socket_close(php_stream *stream, int close_handle)
{
    Socket *sock = (Socket*) stream->abstract;
    delete sock;
    return 0;
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
    Socket *sock = (Socket*) stream->abstract;
    if (!sock)
    {
        return FAILURE;
    }

    switch (castas)
    {
    case PHP_STREAM_AS_STDIO:
        if (ret)
        {
            *(FILE**) ret = fdopen(sock->socket->fd, stream->mode);
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
            *(php_socket_t *) ret = sock->socket->fd;
        return SUCCESS;
    default:
        return FAILURE;
    }
}

static int socket_stat(php_stream *stream, php_stream_statbuf *ssb)
{
    Socket *sock = (Socket*) stream->abstract;
    if (!sock)
    {
        return FAILURE;
    }
    return zend_fstat(sock->socket->fd, &ssb->sb);
}

static inline int socket_connect(php_stream *stream, Socket *sock, php_stream_xport_param *xparam)
{
    char *host = NULL;
    int portno = 0;
    int ret;
    char *ip_address = NULL;

    if (sock->type == SW_SOCK_TCP || sock->type == SW_SOCK_TCP6 || sock->type == SW_SOCK_UDP || sock->type == SW_SOCK_UDP6)
    {
        ip_address = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext,
                &xparam->outputs.error_text);
        host = ip_address;
    }
    else
    {
        host = xparam->inputs.name;
    }
    if (host == NULL)
    {
        return -1;
    }
    if (xparam->inputs.timeout)
    {
        sock->set_timeout(xparam->inputs.timeout);
    }
    if (sock->connect(host, portno) == false)
    {
        xparam->outputs.error_code = sock->errCode;
        ret = -1;
    }
    else
    {
        ret = 0;
    }
    if (ip_address)
    {
        efree(ip_address);
    }
    return ret;
}

static inline int socket_bind(php_stream *stream, Socket *sock, php_stream_xport_param *xparam STREAMS_DC)
{
    char *host = NULL;
    int portno = 0;
    char *ip_address = NULL;

    if (sock->type == SW_SOCK_TCP || sock->type == SW_SOCK_TCP6 || sock->type == SW_SOCK_UDP
            || sock->type == SW_SOCK_UDP6)
    {
        ip_address = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext,
                &xparam->outputs.error_text);
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
    zval *tmpzval = NULL;

    xparam->outputs.client = NULL;

    if ((NULL != PHP_STREAM_CONTEXT(stream))
            && (tmpzval = php_stream_context_get_option(PHP_STREAM_CONTEXT(stream), "socket", "tcp_nodelay")) != NULL
            && zend_is_true(tmpzval))
    {
        tcp_nodelay = 1;
    }

    zend_string **textaddr = xparam->want_textaddr ? &xparam->outputs.textaddr : NULL;
    struct sockaddr **addr = xparam->want_addr ? &xparam->outputs.addr : NULL;
    socklen_t *addrlen = xparam->want_addr ? &xparam->outputs.addrlen : NULL;

    struct timeval *timeout = xparam->inputs.timeout;
    zend_string **error_string = xparam->want_errortext ? &xparam->outputs.error_text : NULL;
    int *error_code = &xparam->outputs.error_code;

    int error = 0;
    php_sockaddr_storage sa;
    socklen_t sl = sizeof(sa);

    if (timeout)
    {
        sock->set_timeout(timeout);
    }

    Socket *clisock = sock->accept();

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
        return -1;
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
        xparam->outputs.client = php_stream_alloc_rel(stream->ops, (void* )clisock, NULL, "r+");
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

#ifdef SW_USE_OPENSSL
#define PHP_SSL_MAX_VERSION_LEN 32

static char *php_ssl_cipher_get_version(const SSL_CIPHER *c, char *buffer, size_t max_len)
{
    const char *version = SSL_CIPHER_get_version(c);
    strncpy(buffer, version, max_len);
    if (max_len <= strlen(version))
    {
        buffer[max_len - 1] = 0;
    }
    return buffer;
}
#endif

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
        ret = (ret == SOCK_CONN_ERR) ? -1 : ret;
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
                *addr = NULL;
                *addrlen = 0;
            }
        }
    }
    else
    {
        ret = sock->recv(buf, buflen);
        ret = (ret == SOCK_CONN_ERR) ? -1 : ret;
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

#define GET_VER_OPT(name)               (PHP_STREAM_CONTEXT(stream) && (val = php_stream_context_get_option(PHP_STREAM_CONTEXT(stream), "ssl", name)) != NULL)
#define GET_VER_OPT_STRING(name, str)   if (GET_VER_OPT(name)) { convert_to_string_ex(val); str = Z_STRVAL_P(val); }
#define GET_VER_OPT_LONG(name, num)     if (GET_VER_OPT(name)) { convert_to_long_ex(val); num = Z_LVAL_P(val); }

static int socket_setup_crypto(php_stream *stream, Socket *sock, php_stream_xport_crypto_param *cparam STREAMS_DC)
{
    return 0;
}

static int socket_enable_crypto(php_stream *stream, Socket *sock, php_stream_xport_crypto_param *cparam STREAMS_DC)
{
    return sock->ssl_handshake() ? 0 : -1;
}
#endif

static inline int socket_xport_api(php_stream *stream, Socket *sock, php_stream_xport_param *xparam STREAMS_DC)
{
    static const int shutdown_how[] = { SHUT_RD, SHUT_WR, SHUT_RDWR };

    switch (xparam->op)
    {
    case STREAM_XPORT_OP_LISTEN:
    {
#ifdef SW_USE_OPENSSL
        if (sock->open_ssl)
        {
            zval *val = NULL;
            char *certfile = NULL;
            char *private_key;

            GET_VER_OPT_STRING("local_cert", certfile);
            GET_VER_OPT_STRING("local_pk", private_key);

            if (!certfile || !private_key)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert/key file not found.");
                return FAILURE;
            }

            sock->ssl_option.cert_file = sw_strdup(certfile);
            sock->ssl_option.key_file = sw_strdup(private_key);
        }
#endif
        xparam->outputs.returncode = sock->listen(xparam->inputs.backlog) ? 0 : -1;
        break;
    }
    case STREAM_XPORT_OP_CONNECT:
    case STREAM_XPORT_OP_CONNECT_ASYNC:
        xparam->outputs.returncode = socket_connect(stream, sock, xparam);
        break;
    case STREAM_XPORT_OP_BIND:
    {
        if (sock->_sock_domain != AF_UNIX)
        {
            zval *tmpzval = NULL;
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
            if ((tmpzval = php_stream_context_get_option(ctx, "socket", "so_reuseport")) != NULL
                    && zend_is_true(tmpzval))
            {
                setsockopt(sock->get_fd(), SOL_SOCKET, SO_REUSEPORT, (char*) &sockoptval, sizeof(sockoptval));
            }
#endif

#ifdef SO_BROADCAST
            if ((tmpzval = php_stream_context_get_option(ctx, "socket", "so_broadcast")) != NULL
                    && zend_is_true(tmpzval))
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
        xparam->outputs.returncode = php_network_get_sock_name(sock->socket->fd,
                xparam->want_textaddr ? &xparam->outputs.textaddr : NULL,
                xparam->want_addr ? &xparam->outputs.addr : NULL, xparam->want_addr ? &xparam->outputs.addrlen : NULL
                );
        break;
    case STREAM_XPORT_OP_GET_PEER_NAME:
        xparam->outputs.returncode = php_network_get_peer_name(sock->socket->fd,
                xparam->want_textaddr ? &xparam->outputs.textaddr : NULL,
                xparam->want_addr ? &xparam->outputs.addr : NULL, xparam->want_addr ? &xparam->outputs.addrlen : NULL
                );
        break;

    case STREAM_XPORT_OP_SEND:
        if ((xparam->inputs.flags & STREAM_OOB) == STREAM_OOB)
        {
            swoole_php_error(E_WARNING, "STREAM_OOB flags is not supports");
            xparam->outputs.returncode = -1;
            break;
        }
        xparam->outputs.returncode = socket_sendto(sock, xparam->inputs.buf, xparam->inputs.buflen, xparam->inputs.addr,
                xparam->inputs.addrlen);
        if (xparam->outputs.returncode == -1)
        {
            char *err = php_socket_strerror(php_socket_errno(), NULL, 0);
            php_error_docref(NULL, E_WARNING, "%s\n", err);
            efree(err);
        }
        break;

    case STREAM_XPORT_OP_RECV:
        if ((xparam->inputs.flags & STREAM_OOB) == STREAM_OOB)
        {
            swoole_php_error(E_WARNING, "STREAM_OOB flags is not supports");
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
                    xparam->want_textaddr ? &xparam->outputs.textaddr : NULL,
                    xparam->want_addr ? &xparam->outputs.addr : NULL,
                    xparam->want_addr ? &xparam->outputs.addrlen : NULL
                    );
        }
        break;
    case STREAM_XPORT_OP_SHUTDOWN:
        xparam->outputs.returncode = sock->shutdown(shutdown_how[xparam->how]);
        break;
    default:
        break;
    }
    return PHP_STREAM_OPTION_RETURN_OK;
}

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
    Socket *sock = (Socket*) stream->abstract;
    switch (option)
    {
    case PHP_STREAM_OPTION_XPORT_API:
        return socket_xport_api(stream, sock, (php_stream_xport_param *) ptrparam STREAMS_CC);

    case PHP_STREAM_OPTION_META_DATA_API:
#ifdef SW_USE_OPENSSL
        if (sock->socket->ssl)
        {
            zval tmp;
            const char *proto_str;
            char version_str[PHP_SSL_MAX_VERSION_LEN];
            const SSL_CIPHER *cipher;

            array_init(&tmp);
            switch (SSL_version(sock->socket->ssl))
            {
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

            cipher = SSL_get_current_cipher(sock->socket->ssl);
            add_assoc_string(&tmp, "protocol", (char* )proto_str);
            add_assoc_string(&tmp, "cipher_name", (char * ) SSL_CIPHER_get_name(cipher));
            add_assoc_long(&tmp, "cipher_bits", SSL_CIPHER_get_bits(cipher, NULL));
            add_assoc_string(&tmp, "cipher_version", php_ssl_cipher_get_version(cipher, version_str, PHP_SSL_MAX_VERSION_LEN));
            add_assoc_zval((zval *)ptrparam, "crypto", &tmp);
        }
#endif
        add_assoc_bool((zval * )ptrparam, "eof", stream->eof);
        break;

    case PHP_STREAM_OPTION_READ_TIMEOUT:
        sock->set_timeout((struct timeval*) ptrparam);
        break;
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
            /* fall through */
            break;
        }
        break;
    }
#endif
    default:
        break;
    }
    return 0;
}

static php_stream *socket_create(const char *proto, size_t protolen, const char *resourcename, size_t resourcenamelen,
        const char *persistent_id, int options, int flags, struct timeval *timeout, php_stream_context *context
        STREAMS_DC)
{
    php_stream *stream = NULL;
    Socket *sock;

    if (unlikely(COROG.active == 0))
    {
        coro_init(TSRMLS_C);
    }

    php_swoole_check_reactor();

    if (strncmp(proto, "unix", protolen) == 0)
    {
        sock = new Socket(SW_SOCK_UNIX_STREAM);
    }
    else if (strncmp(proto, "udp", protolen) == 0)
    {
        sock = new Socket(SW_SOCK_UDP);
    }
    else if (strncmp(proto, "udg", protolen) == 0)
    {
        sock = new Socket(SW_SOCK_UNIX_DGRAM);
    }
#ifdef SW_USE_OPENSSL
    else if (strncmp(proto, "ssl", protolen) == 0)
    {
        sock = new Socket(SW_SOCK_TCP);
        sock->open_ssl = true;
    }
#endif
    else
    {
        sock = new Socket(SW_SOCK_TCP);
    }

    sock->setTimeout((double) FG(default_socket_timeout));
    stream = php_stream_alloc_rel(&socket_ops, sock, persistent_id, "r+");

    if (stream == NULL)
    {
        delete sock;
        return NULL;
    }
    return stream;
}

static PHP_METHOD(swoole_runtime, enableCoroutine)
{
    zend_bool enable = 1;
    zend_long flags = SW_HOOK_ALL;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|bl", &enable, &flags) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (enable)
    {
        if (hook_init)
        {
            RETURN_FALSE;
        }
        hook_flags = flags;
        hook_init = true;
        HashTable *xport_hash = php_stream_xport_get_hash();

        if (flags & SW_HOOK_FILE)
        {
            memcpy((void*) &ori_php_plain_files_wrapper, &php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
            memcpy((void*) &php_plain_files_wrapper, &sw_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
            memcpy((void*) &ori_php_stream_stdio_ops, &php_stream_stdio_ops, sizeof(php_stream_stdio_ops));
            memcpy((void*) &php_stream_stdio_ops, &sw_php_stream_stdio_ops, sizeof(php_stream_stdio_ops));
        }
        if (flags & SW_HOOK_SLEEP)
        {
            ori_sleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("sleep"));
            ori_usleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("usleep"));
            ori_time_nanosleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("time_nanosleep"));
            ori_time_sleep_until = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("time_sleep_until"));

            ori_sleep->internal_function.handler = PHP_FN(_sleep);
            ori_usleep->internal_function.handler = PHP_FN(_usleep);
            ori_time_nanosleep->internal_function.handler = PHP_FN(_time_nanosleep);
            ori_time_sleep_until->internal_function.handler = PHP_FN(_time_sleep_until);
        }
        if (flags & SW_HOOK_TCP)
        {
            ori_factory.tcp = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("tcp"));
            php_stream_xport_register("tcp", socket_create);
        }
        if (flags & SW_HOOK_UNIX)
        {
            ori_factory.unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("unix"));
            php_stream_xport_register("unix", socket_create);
        }
        if (flags & SW_HOOK_UDG)
        {
            ori_factory.unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udg"));
            php_stream_xport_register("udg", socket_create);
        }
        if (flags & SW_HOOK_UDP)
        {
            ori_factory.unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udp"));
            php_stream_xport_register("udp", socket_create);
        }
#ifdef SW_USE_OPENSSL
        if (flags & SW_HOOK_SSL)
        {
            ori_factory.ssl = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("ssl"));
            php_stream_xport_register("ssl", socket_create);
        }
        if (flags & SW_HOOK_TLS)
        {
            ori_factory.tls = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("tls"));
            php_stream_xport_register("tls", socket_create);
        }
#endif
    }
    else
    {
        if (!hook_init)
        {
            RETURN_FALSE;
        }
        if (hook_flags & SW_HOOK_FILE)
        {
            memcpy((void*) &php_plain_files_wrapper, &ori_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
            memcpy((void*) &php_stream_stdio_ops, &ori_php_stream_stdio_ops, sizeof(php_stream_stdio_ops));
        }
        if (flags & SW_HOOK_TCP)
        {
            php_stream_xport_register("tcp", ori_factory.tcp);
        }
        if (flags & SW_HOOK_UNIX)
        {
            php_stream_xport_register("unix", ori_factory.unix);
        }
        if (flags & SW_HOOK_UDP)
        {
            php_stream_xport_register("udp", ori_factory.udp);
        }
        if (flags & SW_HOOK_UDG)
        {
            php_stream_xport_register("udg", ori_factory.udg);
        }
#ifdef SW_USE_OPENSSL
        if (flags & SW_HOOK_SSL)
        {
            php_stream_xport_register("ssl", ori_factory.ssl);
        }
        if (flags & SW_HOOK_TLS)
        {
            php_stream_xport_register("tls", ori_factory.tls);
        }
#endif
    }
}

static PHP_FUNCTION(_sleep)
{
    zend_long num;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &num) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (num < 0)
    {
        php_error_docref(NULL, E_WARNING, "Number of seconds must be greater than or equal to 0");
        RETURN_FALSE;
    }
    php_swoole_check_reactor();
    php_swoole_check_timer(num * 1000);
    swoole_coroutine_sleep((double) num);
    RETURN_LONG(num);
}

static PHP_FUNCTION(_usleep)
{
    zend_long num;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &num) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (num < 0)
    {
        php_error_docref(NULL, E_WARNING, "Number of seconds must be greater than or equal to 0");
        RETURN_FALSE;
    }
    php_swoole_check_reactor();
    php_swoole_check_timer(num / 1000);
    swoole_coroutine_sleep((double) num / 1000000);
}

#if HAVE_NANOSLEEP
static PHP_FUNCTION(_time_nanosleep)
{
    zend_long tv_sec, tv_nsec;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &tv_sec, &tv_nsec) == FAILURE)
    {
        return;
    }

    if (tv_sec < 0)
    {
        php_error_docref(NULL, E_WARNING, "The seconds value must be greater than 0");
        RETURN_FALSE;
    }
    if (tv_nsec < 0)
    {
        php_error_docref(NULL, E_WARNING, "The nanoseconds value must be greater than 0");
        RETURN_FALSE;
    }
    double _time = (double) tv_sec + (double) tv_nsec / 1000000000.00;
    if (_time >= 0.001)
    {
        php_swoole_check_reactor();
        php_swoole_check_timer(_time * 1000);
        swoole_coroutine_sleep(_time);
    }
    else
    {
        PHP_FN(time_nanosleep)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    }
}

static PHP_FUNCTION(_time_sleep_until)
{
    double d_ts, c_ts;
    struct timeval tm;
    struct timespec php_req, php_rem;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &d_ts) == FAILURE)
    {
        return;
    }

    if (gettimeofday((struct timeval *) &tm, NULL) != 0)
    {
        RETURN_FALSE;
    }

    c_ts = (double) (d_ts - tm.tv_sec - tm.tv_usec / 1000000.00);
    if (c_ts < 0)
    {
        php_error_docref(NULL, E_WARNING, "Sleep until to time is less than current time");
        RETURN_FALSE;
    }

    php_req.tv_sec = (time_t) c_ts;
    if (php_req.tv_sec > c_ts)
    {
        php_req.tv_sec--;
    }
    php_req.tv_nsec = (long) ((c_ts - php_req.tv_sec) * 1000000000.00);

    double _time = (double) php_req.tv_sec + (double) php_req.tv_nsec / 1000000000.00;
    if (_time >= 0.001)
    {
        php_swoole_check_reactor();
        php_swoole_check_timer(_time * 1000);
        swoole_coroutine_sleep(_time);
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
#endif
