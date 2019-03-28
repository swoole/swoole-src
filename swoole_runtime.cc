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

#include <unordered_map>
#include <initializer_list>

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
static PHP_FUNCTION(_stream_select);
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

static zend_class_entry swoole_runtime_ce;
static zend_class_entry *swoole_runtime_ce_ptr;
static zend_object_handlers swoole_runtime_handlers;

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

typedef struct
{
    php_netstream_data_t stream;
    double read_timeout;
    Socket *socket;
} php_swoole_netstream_data_t;

static bool hook_init = false;
static int hook_flags = 0;

static struct
{
    php_stream_transport_factory tcp;
    php_stream_transport_factory udp;
    php_stream_transport_factory _unix;
    php_stream_transport_factory udg;
#ifdef SW_USE_OPENSSL
    php_stream_transport_factory ssl;
    php_stream_transport_factory tls;
#endif
} ori_factory = {
    nullptr,
    nullptr,
    nullptr,
    nullptr,
#ifdef SW_USE_OPENSSL
    nullptr,
    nullptr,
#endif
};

static php_stream_wrapper ori_php_plain_files_wrapper;

#if PHP_VERSION_ID < 70200
typedef void (*zif_handler)(INTERNAL_FUNCTION_PARAMETERS);
#endif
static zend_function *ori_sleep;
static zif_handler ori_sleep_handler;
static zend_function *ori_usleep;
static zif_handler ori_usleep_handler;
static zend_function *ori_time_nanosleep;
static zif_handler ori_time_nanosleep_handler;
static zend_function *ori_time_sleep_until;
static zif_handler ori_time_sleep_until_handler;
static zend_function *ori_gethostbyname;
static zif_handler ori_gethostbyname_handler;
static zend_function *ori_stream_select;
static zif_handler ori_stream_select_handler;

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

void swoole_runtime_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_runtime, "Swoole\\Runtime", "swoole_runtime", NULL, swoole_runtime_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_runtime, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_runtime, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_runtime, zend_class_unset_property_deny);

    SWOOLE_DEFINE(HOOK_TCP);
    SWOOLE_DEFINE(HOOK_UDP);
    SWOOLE_DEFINE(HOOK_UNIX);
    SWOOLE_DEFINE(HOOK_UDG);
    SWOOLE_DEFINE(HOOK_SSL);
    SWOOLE_DEFINE(HOOK_TLS);
    SWOOLE_DEFINE(HOOK_FILE);
    SWOOLE_DEFINE(HOOK_SLEEP);
    SWOOLE_DEFINE(HOOK_STREAM_SELECT);
    SWOOLE_DEFINE(HOOK_BLOCKING_FUNCTION);
    SWOOLE_DEFINE(HOOK_ALL);
}

static auto block_io_functions = {
    "sleep",
    "usleep",
    "time_nanosleep",
    "time_sleep_until",
    "file_get_contents",
    "curl_init",
    "stream_select",
    "pcntl_fork",
    "popen",
    "socket_select",
    "gethostbyname",
};

static auto block_io_classes = {
    "redis", "pdo", "mysqli",
};

static bool enable_strict_mode = false;

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
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return 0;
    }
    Socket *sock = (Socket*) abstract->socket;
    ssize_t didwrite;
    if (UNEXPECTED(!sock))
    {
        return 0;
    }
    didwrite = sock->send_all(buf, count);
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
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return 0;
    }
    Socket *sock = (Socket*) abstract->socket;
    ssize_t nr_bytes = 0;
    if (UNEXPECTED(!sock))
    {
        return 0;
    }
    sock->set_timeout(abstract->read_timeout, SW_TIMEOUT_READ);
    nr_bytes = sock->recv(buf, count);
    /**
     * sock->errCode != ETIMEDOUT : Compatible with sync blocking IO
     */
    stream->eof = (nr_bytes == 0 || (nr_bytes == -1 && sock->errCode != ETIMEDOUT && swConnection_error(sock->errCode) == SW_CLOSE));
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
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return FAILURE;
    }
    /** set it null immediately */
    stream->abstract = NULL;
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
    return zend_fstat(sock->socket->fd, &ssb->sb);
}

static inline int socket_connect(php_stream *stream, Socket *sock, php_stream_xport_param *xparam)
{
    char *host = NULL;
    int portno = 0;
    int ret = 0;
    char *ip_address = NULL;

    if (UNEXPECTED(sock->socket == nullptr))
    {
        return FAILURE;
    }

    if (sock->type == SW_SOCK_TCP || sock->type == SW_SOCK_TCP6 || sock->type == SW_SOCK_UDP || sock->type == SW_SOCK_UDP6)
    {
        ip_address = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext,
                &xparam->outputs.error_text);
        host = ip_address;
        if (sock->sock_type == SOCK_STREAM)
        {
            int sockoptval = 1;
            setsockopt(sock->get_fd(), IPPROTO_TCP, TCP_NODELAY, (char*) &sockoptval, sizeof(sockoptval));
        }
    }
    else
    {
        host = xparam->inputs.name;
    }
    if (host == NULL)
    {
        return FAILURE;
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
            && zval_is_true(tmpzval))
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
        sock->set_timeout(timeout, SW_TIMEOUT_READ);
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

        xparam->outputs.client = php_stream_alloc_rel(stream->ops, (void* )abstract, NULL, "r+");
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
            char *private_key = NULL;

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
        if (sock->sock_domain != AF_UNIX)
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
                    && zval_is_true(tmpzval))
            {
                setsockopt(sock->get_fd(), SOL_SOCKET, SO_REUSEPORT, (char*) &sockoptval, sizeof(sockoptval));
            }
#endif

#ifdef SO_BROADCAST
            if ((tmpzval = php_stream_context_get_option(ctx, "socket", "so_broadcast")) != NULL
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
    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t *) stream->abstract;
    if (UNEXPECTED(!abstract))
    {
        return FAILURE;
    }
    Socket *sock = (Socket*) abstract->socket;
    struct timeval default_timeout = { 0, 0 };
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
        add_assoc_bool((zval * )ptrparam, "timed_out", sock->errCode == ETIMEDOUT);
        add_assoc_bool((zval * )ptrparam, "eof", stream->eof);
        add_assoc_bool((zval * )ptrparam, "blocked", 1);
        break;

    case PHP_STREAM_OPTION_READ_TIMEOUT:
        default_timeout = *(struct timeval*) ptrparam;
        abstract->read_timeout = (double) default_timeout.tv_sec + ((double) default_timeout.tv_usec / 1000 / 1000);
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
    return SUCCESS;
}

static php_stream *php_socket_create(
    const char *proto, size_t protolen, const char *resourcename, size_t resourcenamelen,
    const char *persistent_id, int options, int flags, struct timeval *timeout, php_stream_context *context
    STREAMS_DC
)
{
    php_stream_transport_factory ori_call;

    if (strncmp(proto, "unix", protolen) == 0)
    {
        ori_call = ori_factory._unix;
    }
    else if (strncmp(proto, "udp", protolen) == 0)
    {
        ori_call = ori_factory.udp;
    }
    else if (strncmp(proto, "udg", protolen) == 0)
    {
        ori_call = ori_factory.udg;
    }
#ifdef SW_USE_OPENSSL
    else if (strncmp(proto, "ssl", protolen) == 0)
    {
        ori_call = ori_factory.ssl;
    }
    else if (strncmp(proto, "tls", protolen) == 0)
    {
        ori_call = ori_factory.tls;
    }
#endif
    else
    {
        ori_call = ori_factory.tcp;
    }
    return ori_call(proto, protolen, resourcename, resourcenamelen, persistent_id, options, flags, timeout, context STREAMS_CC);
}

static php_stream *socket_create(
    const char *proto, size_t protolen, const char *resourcename, size_t resourcenamelen,
    const char *persistent_id, int options, int flags, struct timeval *timeout, php_stream_context *context
    STREAMS_DC
)
{
    php_stream *stream = NULL;
    Socket *sock;

    if (unlikely(SwooleG.main_reactor == nullptr || !Coroutine::get_current()))
    {
        return php_socket_create(proto, protolen, resourcename, resourcenamelen, persistent_id, options, flags, timeout, context STREAMS_CC);
    }

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
    else if (strncmp(proto, "ssl", protolen) == 0 || strncmp(proto, "tls", protolen) == 0)
    {
        sock = new Socket(SW_SOCK_TCP);
        sock->open_ssl = true;
    }
#endif
    else
    {
        sock = new Socket(SW_SOCK_TCP);
    }

    if (UNEXPECTED(sock->socket == nullptr))
    {
        _failed:
        swoole_php_fatal_error(E_WARNING, "new Socket() failed. Error: %s [%d]", strerror(errno), errno);
        delete sock;
        return NULL;
    }

    if (FG(default_socket_timeout) > 0)
    {
        sock->set_timeout((double) FG(default_socket_timeout));
    }

    php_swoole_netstream_data_t *abstract = (php_swoole_netstream_data_t*) emalloc(sizeof(*abstract));
    memset(abstract, 0, sizeof(*abstract));

    abstract->socket = sock;
    abstract->stream.timeout.tv_sec = FG(default_socket_timeout);
    abstract->stream.socket = sock->get_fd();
    abstract->read_timeout = (double) FG(default_socket_timeout);

    persistent_id = nullptr;//prevent stream api in user level using pconnect to persist the socket
    stream = php_stream_alloc_rel(&socket_ops, abstract, persistent_id, "r+");

    if (stream == NULL)
    {
        goto _failed;
    }
    return stream;
}

bool PHPCoroutine::enable_hook(int flags)
{
    if (unlikely(enable_strict_mode))
    {
        swoole_php_fatal_error(E_ERROR, "unable to enable the coroutine mode after you enable the strict mode.");
    }
    if (hook_init)
    {
        return false;
    }
    hook_flags = flags;
    hook_init = true;
    HashTable *xport_hash = php_stream_xport_get_hash();

    if (flags & SW_HOOK_FILE)
    {
        memcpy((void*) &ori_php_plain_files_wrapper, &php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
        memcpy((void*) &php_plain_files_wrapper, &sw_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
    }
    if (flags & SW_HOOK_SLEEP)
    {
        ori_sleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("sleep"));
        if (ori_sleep)
        {
            ori_sleep_handler =  ori_sleep->internal_function.handler;
            ori_sleep->internal_function.handler = PHP_FN(_sleep);
        }
        ori_usleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("usleep"));
        if (ori_usleep)
        {
            ori_usleep_handler =  ori_usleep->internal_function.handler;
            ori_usleep->internal_function.handler = PHP_FN(_usleep);
        }
        ori_time_nanosleep = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("time_nanosleep"));
        if (ori_time_nanosleep)
        {
            ori_time_nanosleep_handler =  ori_time_nanosleep->internal_function.handler;
            ori_time_nanosleep->internal_function.handler = PHP_FN(_time_nanosleep);
        }
        ori_time_sleep_until = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("time_sleep_until"));
        if (ori_time_sleep_until)
        {
            ori_time_sleep_until_handler =  ori_time_sleep_until->internal_function.handler;
            ori_time_sleep_until->internal_function.handler = PHP_FN(_time_sleep_until);
        }
    }
    if (flags & SW_HOOK_STREAM_SELECT)
    {
        ori_stream_select = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("stream_select"));
        if (ori_stream_select)
        {
            ori_stream_select_handler =  ori_stream_select->internal_function.handler;
            ori_stream_select->internal_function.handler = PHP_FN(_stream_select);
        }
    }
    if (flags & SW_HOOK_BLOCKING_FUNCTION)
    {
        ori_gethostbyname = (zend_function *) zend_hash_str_find_ptr(EG(function_table), ZEND_STRL("gethostbyname"));
        if (ori_gethostbyname)
        {
            ori_gethostbyname_handler =  ori_gethostbyname->internal_function.handler;
            ori_gethostbyname->internal_function.handler = PHP_FN(swoole_coroutine_gethostbyname);
        }
    }
    if (flags & SW_HOOK_TCP)
    {
        ori_factory.tcp = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("tcp"));
        php_stream_xport_register("tcp", socket_create);
    }
    if (flags & SW_HOOK_UNIX)
    {
        ori_factory._unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("unix"));
        php_stream_xport_register("unix", socket_create);
    }
    if (flags & SW_HOOK_UDG)
    {
        ori_factory._unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udg"));
        php_stream_xport_register("udg", socket_create);
    }
    if (flags & SW_HOOK_UDP)
    {
        ori_factory._unix = (php_stream_transport_factory) zend_hash_str_find_ptr(xport_hash, ZEND_STRL("udp"));
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
    return true;
}

bool PHPCoroutine::disable_hook()
{
    if (!hook_init)
    {
        return false;
    }
    if (hook_flags & SW_HOOK_FILE)
    {
        memcpy((void*) &php_plain_files_wrapper, &ori_php_plain_files_wrapper, sizeof(php_plain_files_wrapper));
    }
    if (hook_flags & SW_HOOK_SLEEP)
    {
        if (ori_sleep)
        {
            ori_sleep->internal_function.handler = ori_sleep_handler;
        }
        if (ori_usleep)
        {
            ori_usleep->internal_function.handler = ori_usleep_handler;
        }
        if (ori_time_nanosleep)
        {
            ori_time_nanosleep->internal_function.handler = ori_time_nanosleep_handler;
        }
        if (ori_time_sleep_until)
        {
            ori_time_sleep_until->internal_function.handler = ori_time_sleep_until_handler;
        }
    }
    if (hook_flags & SW_HOOK_STREAM_SELECT)
    {
        if (ori_stream_select)
        {
            ori_stream_select->internal_function.handler = ori_stream_select_handler;
        }
    }
    if (hook_flags & SW_HOOK_BLOCKING_FUNCTION)
    {
        if (ori_gethostbyname)
        {
            ori_gethostbyname->internal_function.handler = ori_gethostbyname_handler;
        }
    }
    if (hook_flags & SW_HOOK_TCP)
    {
        php_stream_xport_register("tcp", ori_factory.tcp);
    }
    if (hook_flags & SW_HOOK_UNIX)
    {
        php_stream_xport_register("unix", ori_factory._unix);
    }
    if (hook_flags & SW_HOOK_UDP)
    {
        php_stream_xport_register("udp", ori_factory.udp);
    }
    if (hook_flags & SW_HOOK_UDG)
    {
        php_stream_xport_register("udg", ori_factory.udg);
    }
#ifdef SW_USE_OPENSSL
    if (hook_flags & SW_HOOK_SSL)
    {
        php_stream_xport_register("ssl", ori_factory.ssl);
    }
    if (hook_flags & SW_HOOK_TLS)
    {
        php_stream_xport_register("tls", ori_factory.tls);
    }
#endif
    hook_flags = 0;
    return true;
}

static PHP_METHOD(swoole_runtime, enableCoroutine)
{
    zval *zenable = nullptr;
    zend_bool enable = 1;
    zend_long flags = SW_HOOK_ALL;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(zenable)
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zenable)
    {
        if (Z_TYPE_P(zenable) == IS_LONG)
        {
            enable = (flags = Z_LVAL_P(zenable)) > 0;
        }
        else
        {
            enable = zval_is_true(zenable);
        }
    }

    if (enable)
    {
        RETURN_BOOL(PHPCoroutine::enable_hook(flags));
    }
    else
    {
        RETURN_BOOL(PHPCoroutine::disable_hook());
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

    if (num >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        RETURN_LONG(Coroutine::sleep((double ) num) < 0 ? num : 0);
    }
    else
    {
        RETURN_LONG(php_sleep(num));
    }
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
    double _time = (double) num / 1000000;

    if (_time >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        Coroutine::sleep((double) num / 1000000);
    }
    else
    {
        usleep((unsigned int)num);
    }
}

static PHP_FUNCTION(_time_nanosleep)
{
    zend_long tv_sec, tv_nsec;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &tv_sec, &tv_nsec) == FAILURE)
    {
        RETURN_FALSE;
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
    if (_time >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        Coroutine::sleep(_time);
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
            swoole_php_error(E_WARNING, "nanoseconds was not in the range 0 to 999 999 999 or seconds was negative");
        }
    }
}

static PHP_FUNCTION(_time_sleep_until)
{
    double d_ts, c_ts;
    struct timeval tm;
    struct timespec php_req, php_rem;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &d_ts) == FAILURE)
    {
        RETURN_FALSE;
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
    if (_time >= SW_TIMER_MIN_SEC && Coroutine::get_current())
    {
        Coroutine::sleep(_time);
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
    php_socket_t sock;

    if (Z_TYPE_P(stream_array) != IS_ARRAY)
    {
        return;
    }

    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(stream_array), elem)
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
            fds.emplace(make_pair(sock, socket_poll_fd(event, elem)));
        }
        else
        {
            i->second.events |= event;
        }
    } ZEND_HASH_FOREACH_END();
}

static int stream_array_emulate_read_fd_set(zval *stream_array)
{
    zval *elem, *dest_elem, new_array;
    php_stream *stream;
    int ret = 0;

    if (Z_TYPE_P(stream_array) != IS_ARRAY)
    {
        return 0;
    }

    ZVAL_NEW_ARR(&new_array);
    zend_hash_init(Z_ARRVAL(new_array), zend_hash_num_elements(Z_ARRVAL_P(stream_array)), NULL, ZVAL_PTR_DTOR, 0);

    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(stream_array), elem)
    {
        ZVAL_DEREF(elem);
        php_stream_from_zval_no_verify(stream, elem);
        if (stream == NULL)
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
            dest_elem = zend_hash_next_index_insert(Z_ARRVAL(new_array), elem);
            if (dest_elem)
            {
                zval_add_ref(dest_elem);
            }
            ret++;
            continue;
        }
    } ZEND_HASH_FOREACH_END();

    if (ret > 0)
    {
        /* destroy old array and add new one */
        zend_array_destroy(Z_ARR_P(stream_array));
        Z_ARR_P(stream_array) = Z_ARR(new_array);
    }
    else
    {
        zend_array_destroy(Z_ARR(new_array));
    }

    return ret;
}

static PHP_FUNCTION(_stream_select)
{
    if (!Coroutine::get_current())
    {
        ori_stream_select_handler(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    zval *r_array, *w_array, *e_array;
    zend_long sec, usec = 0;
    zend_bool secnull;
    int retval = 0;

    ZEND_PARSE_PARAMETERS_START(4, 5)
        Z_PARAM_ARRAY_EX2(r_array, 1, 1, 0)
        Z_PARAM_ARRAY_EX2(w_array, 1, 1, 0)
        Z_PARAM_ARRAY_EX2(e_array, 1, 1, 0)
        Z_PARAM_LONG_EX(sec, secnull, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(usec)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    std::unordered_map<int, socket_poll_fd> fds;

    if (r_array != NULL)
    {
        stream_array_to_fd_set(r_array, fds, SW_EVENT_READ);
    }

    if (w_array != NULL)
    {
        stream_array_to_fd_set(w_array, fds, SW_EVENT_WRITE);
    }

    if (e_array != NULL)
    {
        stream_array_to_fd_set(e_array, fds, SW_EVENT_ERROR);
    }

    if (fds.size() == 0)
    {
        php_error_docref(NULL, E_WARNING, "No stream arrays were passed");
        RETURN_FALSE;
    }

    double timeout = -1;
    if (!secnull)
    {
        if (sec < 0)
        {
            php_error_docref(NULL, E_WARNING, "The seconds parameter must be greater than 0");
            RETURN_FALSE
        }
        else if (usec < 0)
        {
            php_error_docref(NULL, E_WARNING, "The microseconds parameter must be greater than 0");
            RETURN_FALSE
        }
        timeout = (double) sec + ((double) usec / 1000000);
    }

    /* slight hack to support buffered data; if there is data sitting in the
     * read buffer of any of the streams in the read array, let's pretend
     * that we selected, but return only the readable sockets */
    if (r_array != NULL)
    {
        retval = stream_array_emulate_read_fd_set(r_array);
        if (retval > 0)
        {
            if (w_array != NULL)
            {
                zend_hash_clean(Z_ARRVAL_P(w_array));
            }
            if (e_array != NULL)
            {
                zend_hash_clean(Z_ARRVAL_P(e_array));
            }
            RETURN_LONG(retval);
        }
    }

    /**
     * timeout
     */
    if (!Coroutine::socket_poll(fds, timeout))
    {
        RETURN_LONG(0);
    }

    if (r_array != NULL)
    {
        zend_hash_clean(Z_ARRVAL_P(r_array));
    }
    if (w_array != NULL)
    {
        zend_hash_clean(Z_ARRVAL_P(w_array));
    }
    if (e_array != NULL)
    {
        zend_hash_clean(Z_ARRVAL_P(e_array));
    }

    for (auto i = fds.begin(); i != fds.end(); i++)
    {
        zval *zsocket = (zval *) i->second.ptr;
        int revents = i->second.revents;
        if (revents == 0)
        {
            continue;
        }
        SW_ASSERT((revents &= ((~SW_EVENT_READ) | (~SW_EVENT_WRITE) | (~SW_EVENT_ERROR))) == 0);
        if ((revents & SW_EVENT_READ) && r_array)
        {
            if (EXPECTED(add_next_index_zval(r_array, zsocket) == SUCCESS))
            {
                Z_TRY_ADDREF_P(zsocket);
            }
        }
        if ((revents & SW_EVENT_WRITE) && w_array)
        {
            if (EXPECTED(add_next_index_zval(w_array, zsocket) == SUCCESS))
            {
                Z_TRY_ADDREF_P(zsocket);
            }
        }
        if ((revents & SW_EVENT_ERROR) && e_array)
        {
            if (EXPECTED(add_next_index_zval(e_array, zsocket) == SUCCESS))
            {
                Z_TRY_ADDREF_P(zsocket);
            }
        }
        retval++;
    }

    RETURN_LONG(retval);
}
