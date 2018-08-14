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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */
#include "php_swoole.h"
#include "swoole_coroutine.h"
#include "Socket.h"

#include <unordered_map>
#include <initializer_list>

using namespace swoole;
using namespace std;

extern "C"
{
static PHP_METHOD(swoole_runtime, enableStrictMode);
static PHP_METHOD(swoole_runtime, enableCoroutine);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_class_entry *ce;
static unordered_map<int, Socket*> _sockets;
static php_stream_ops origin_socket_ops;
static bool hook_init = false;

static const zend_function_entry swoole_runtime_methods[] =
{
    PHP_ME(swoole_runtime, enableStrictMode, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_runtime, enableCoroutine, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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
    php_netstream_data_t *sock = (php_netstream_data_t*) stream->abstract;
    int didwrite;
    struct timeval *ptimeout;

    if (!sock || sock->socket == -1)
    {
        return 0;
    }

    if (sock->timeout.tv_sec == -1)
    {
        ptimeout = NULL;
    }
    else
    {
        ptimeout = &sock->timeout;
    }

    Socket *_sock = _sockets[sock->socket];
    if (ptimeout)
    {
        _sock->setTimeout((double) ptimeout->tv_sec + ptimeout->tv_usec / 1000000);
    }

    didwrite = _sock->send_all(buf, count);
    if (didwrite <= 0)
    {
        int err = _sock->errCode;
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
    php_netstream_data_t *sock = (php_netstream_data_t*) stream->abstract;
    ssize_t nr_bytes = 0;
    int err;
    struct timeval *ptimeout;

    if (!sock || sock->socket == -1)
    {
        return 0;
    }

    if (sock->timeout.tv_sec == -1)
    {
        ptimeout = NULL;
    }
    else
    {
        ptimeout = &sock->timeout;
    }

    Socket *_sock = _sockets[sock->socket];
    if (ptimeout)
    {
        _sock->setTimeout((double) ptimeout->tv_sec + ptimeout->tv_usec / 1000000);
    }

    nr_bytes = _sock->recv(buf, count);
    err = _sock->errCode;
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

static int socket_close(php_stream *stream, int close_handle)
{
    php_netstream_data_t *sock = (php_netstream_data_t*) stream->abstract;
    int fd = sock->socket;
    origin_socket_ops.close(stream, close_handle);
    Socket *_sock = _sockets[fd];
    _sock->socket->fd = -1;
    delete _sock;
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
} op;

static inline int socket_connect(php_stream *stream, php_netstream_data_t *sock, php_stream_xport_param *xparam)
{
    char *host = NULL, *bindto = NULL;
    int portno, bindport = 0;
    int err = 0;
    int ret;
    zval *tmpzval = NULL;
    long sockopts = STREAM_SOCKOP_NONE;

    host = parse_ip_address_ex(xparam->inputs.name, xparam->inputs.namelen, &portno, xparam->want_errortext,
            &xparam->outputs.error_text);
    if (host == NULL)
    {
        return -1;
    }

    Socket *_sock = new Socket(SW_SOCK_TCP);
    if (_sock->connect(host, portno) == false)
    {
        ret = -1;
        delete _sock;
        goto _return;
    }

    _sockets[_sock->socket->fd] = _sock;
    sock->socket = _sock->socket->fd;

    ret = sock->socket == -1 ? -1 : 0;
    xparam->outputs.error_code = err;

    _return:
    if (host)
    {
        efree(host);
    }
    if (bindto)
    {
        efree(bindto);
    }
    return ret;
}

static int socket_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
    php_netstream_data_t *sock = (php_netstream_data_t*) stream->abstract;
    php_stream_xport_param *xparam;

    if (unlikely(stream->ops->set_option != socket_set_option))
    {
        origin_socket_ops.set_option = stream->ops->set_option;
        origin_socket_ops.read = stream->ops->read;
        origin_socket_ops.write = stream->ops->write;
        origin_socket_ops.close = stream->ops->close;

        stream->ops->set_option = socket_set_option;
        stream->ops->read = socket_read;
        stream->ops->write = socket_write;
        stream->ops->close = socket_close;
    }

    switch (option)
    {
    case PHP_STREAM_OPTION_XPORT_API:
        xparam = (php_stream_xport_param *) ptrparam;
        switch (xparam->op)
        {
        case STREAM_XPORT_OP_CONNECT:
        case STREAM_XPORT_OP_CONNECT_ASYNC:
            xparam->outputs.returncode = socket_connect(stream, sock, xparam);
            return PHP_STREAM_OPTION_RETURN_OK;
        default:
            break;
        }
    }
    return 0;
}

static PHP_METHOD(swoole_runtime, enableCoroutine)
{
    if (hook_init)
    {
        return;
    }
    hook_init = true;
    if (COROG.active == 0)
    {
        coro_init(TSRMLS_C);
    }
    php_swoole_check_reactor();

    origin_socket_ops.set_option = php_stream_socket_ops.set_option;
    origin_socket_ops.read = php_stream_socket_ops.read;
    origin_socket_ops.write = php_stream_socket_ops.write;
    origin_socket_ops.close = php_stream_socket_ops.close;

    php_stream_socket_ops.set_option = socket_set_option;
    php_stream_socket_ops.read = socket_read;
    php_stream_socket_ops.write = socket_write;
    php_stream_socket_ops.close = socket_close;
}
