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
#include "ext/standard/file.h"
#include "swoole_coroutine.h"
#include "socket.h"

#include <unordered_map>
#include <initializer_list>

using namespace swoole;
using namespace std;

extern "C"
{
static PHP_METHOD(swoole_runtime, enableStrictMode);
static PHP_METHOD(swoole_runtime, enableCoroutine);
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
    // int err;
    // struct timeval *ptimeout;

    if (!sock)
    {
        return 0;
    }

    nr_bytes = sock->recv(buf, count);
    // err = sock->errCode;
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
    STREAM_XPORT_OP_SHUTDOWN
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

    if (sock->type == SW_SOCK_TCP || sock->type == SW_SOCK_TCP6)
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

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
    Socket *sock = (Socket*) stream->abstract;
    php_stream_xport_param *xparam;

    switch (option)
    {
    case PHP_STREAM_OPTION_XPORT_API:
        xparam = (php_stream_xport_param *) ptrparam;
        switch (xparam->op)
        {
        case STREAM_XPORT_OP_CONNECT:
        case STREAM_XPORT_OP_CONNECT_ASYNC:
            xparam->outputs.returncode = socket_connect(stream, sock, xparam);
           break;
        default:
            break;
        }
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
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|b", &enable) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (enable)
    {
        if (likely(hook_init))
        {
            RETURN_FALSE;
        }
        hook_init = true;
        php_stream_xport_register("tcp", socket_create);
        php_stream_xport_register("unix", socket_create);
    }
    else
    {
        if (!hook_init)
        {
            RETURN_FALSE;
        }
        php_stream_xport_register("tcp", php_stream_generic_socket_factory);
        php_stream_xport_register("unix", php_stream_generic_socket_factory);
    }
}
