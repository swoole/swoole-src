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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include <string>

namespace swoole
{

class Exception
{
public:
    int code;

    Exception(enum swErrorCode _code)
    {
        code = _code;
    }
};
}

const char* swstrerror(enum swErrorCode code)
{
    /* swstrerror {{{*/
    switch(code)
    {
    case SW_ERROR_MALLOC_FAIL:
        return "malloc fail";
    case SW_ERROR_SYSTEM_CALL_FAIL:
        return "system call fail";
    case SW_ERROR_PHP_FATAL_ERROR:
        return "php fatal error";
    case SW_ERROR_NAME_TOO_LONG:
        return "name too long";
    case SW_ERROR_INVALID_PARAMS:
        return "invalid params";
    case SW_ERROR_QUEUE_FULL:
        return "queue full";
    case SW_ERROR_FILE_NOT_EXIST:
        return "file not exist";
    case SW_ERROR_FILE_TOO_LARGE:
        return "file too large";
    case SW_ERROR_FILE_EMPTY:
        return "file empty";
    case SW_ERROR_DNSLOOKUP_DUPLICATE_REQUEST:
        return "dnslookup duplicate request";
    case SW_ERROR_DNSLOOKUP_RESOLVE_FAILED:
        return "dnslookup resolve failed";
    case SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT:
        return "dnslookup resolve timeout";
    case SW_ERROR_BAD_IPV6_ADDRESS:
        return "bad ipv6 address";
    case SW_ERROR_UNREGISTERED_SIGNAL:
        return "unregistered signal";
    case SW_ERROR_SESSION_CLOSED_BY_SERVER:
        return "session closed by server";
    case SW_ERROR_SESSION_CLOSED_BY_CLIENT:
        return "session closed by client";
    case SW_ERROR_SESSION_CLOSING:
        return "session closing";
    case SW_ERROR_SESSION_CLOSED:
        return "session closed";
    case SW_ERROR_SESSION_NOT_EXIST:
        return "session not exist";
    case SW_ERROR_SESSION_INVALID_ID:
        return "session invalid id";
    case SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA:
        return "session discard timeout data";
    case SW_ERROR_OUTPUT_BUFFER_OVERFLOW:
        return "output buffer overflow";
    case SW_ERROR_SSL_NOT_READY:
        return "ssl not ready";
    case SW_ERROR_SSL_CANNOT_USE_SENFILE:
        return "ssl cannot use senfile";
    case SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE:
        return "ssl empty peer certificate";
    case SW_ERROR_SSL_VEFIRY_FAILED:
        return "ssl vefiry failed";
    case SW_ERROR_SSL_BAD_CLIENT:
        return "ssl bad client";
    case SW_ERROR_SSL_BAD_PROTOCOL:
        return "ssl bad protocol";
    case SW_ERROR_PACKAGE_LENGTH_TOO_LARGE:
        return "package length too large";
    case SW_ERROR_DATA_LENGTH_TOO_LARGE:
        return "data length too large";
    case SW_ERROR_TASK_PACKAGE_TOO_BIG:
        return "task package too big";
    case SW_ERROR_TASK_DISPATCH_FAIL:
        return "task dispatch fail";
    case SW_ERROR_HTTP2_STREAM_ID_TOO_BIG:
        return "http2 stream id too big";
    case SW_ERROR_HTTP2_STREAM_NO_HEADER:
        return "http2 stream no header";
    case SW_ERROR_HTTP2_STREAM_NOT_FOUND:
        return "http2 stream not found";
    case SW_ERROR_AIO_BAD_REQUEST:
        return "aio bad request";
    case SW_ERROR_AIO_CANCELED:
        return "aio canceled";
    case SW_ERROR_CLIENT_NO_CONNECTION:
        return "client no connection";
    case SW_ERROR_SOCKET_CLOSED:
        return "socket closed";
    case SW_ERROR_SOCKS5_UNSUPPORT_VERSION:
        return "socks5 unsupport version";
    case SW_ERROR_SOCKS5_UNSUPPORT_METHOD:
        return "socks5 unsupport method";
    case SW_ERROR_SOCKS5_AUTH_FAILED:
        return "socks5 auth failed";
    case SW_ERROR_SOCKS5_SERVER_ERROR:
        return "socks5 server error";
    case SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR:
        return "http proxy handshake error";
    case SW_ERROR_HTTP_INVALID_PROTOCOL:
        return "http invalid protocol";
    case SW_ERROR_WEBSOCKET_BAD_CLIENT:
        return "websocket bad client";
    case SW_ERROR_WEBSOCKET_BAD_OPCODE:
        return "websocket bad opcode";
    case SW_ERROR_WEBSOCKET_UNCONNECTED:
        return "websocket unconnected";
    case SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED:
        return "websocket handshake failed";
    case SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT:
        return "server must created before client";
    case SW_ERROR_SERVER_TOO_MANY_SOCKET:
        return "server too many socket";
    case SW_ERROR_SERVER_WORKER_TERMINATED:
        return "server worker terminated";
    case SW_ERROR_SERVER_INVALID_LISTEN_PORT:
        return "server invalid listen port";
    case SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT:
        return "server too many listen port";
    case SW_ERROR_SERVER_PIPE_BUFFER_FULL:
        return "server pipe buffer full";
    case SW_ERROR_SERVER_NO_IDLE_WORKER:
        return "server no idle worker";
    case SW_ERROR_SERVER_ONLY_START_ONE:
        return "server only start one";
    case SW_ERROR_SERVER_SEND_IN_MASTER:
        return "server send in master";
    case SW_ERROR_SERVER_INVALID_REQUEST:
        return "server invalid request";
    case SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT:
        return "server worker exit timeout";
    case SW_ERROR_CO_OUT_OF_COROUTINE:
        return "coroutine out of coroutine";
    case SW_ERROR_CO_HAS_BEEN_BOUND:
        return "coroutine has been bound";
    case SW_ERROR_CO_MUTEX_DOUBLE_UNLOCK:
        return "coroutine mutex double unlock";
    case SW_ERROR_CO_BLOCK_OBJECT_LOCKED:
        return "coroutine block object locked";
    case SW_ERROR_CO_BLOCK_OBJECT_WAITING:
        return "coroutine block object waiting";
    case SW_ERROR_CO_YIELD_FAILED:
        return "coroutine yield failed";
    case SW_ERROR_CO_GETCONTEXT_FAILED:
        return "coroutine getcontext failed";
    case SW_ERROR_CO_SWAPCONTEXT_FAILED:
        return "coroutine swapcontext failed";
    case SW_ERROR_CO_MAKECONTEXT_FAILED:
        return "coroutine makecontext failed";
    case SW_ERROR_CO_IOCPINIT_FAILED:
        return "coroutine iocpinit failed";
    case SW_ERROR_CO_PROTECT_STACK_FAILED:
        return "coroutine protect stack failed";
    case SW_ERROR_CO_STD_THREAD_LINK_ERROR:
        return "coroutine std thread link error";
    case SW_ERROR_CO_DISABLED_MULTI_THREAD:
        return "coroutine disabled multi thread";
    default: 
        return "Unknown error";
    }
/*}}}*/
}

void swoole_throw_error(enum swErrorCode code)
{
    throw swoole::Exception(code);
}
