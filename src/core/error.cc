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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"

#include <unordered_set>

static std::unordered_set<int> ignored_errors;

namespace swoole {
Exception::Exception(int code) throw() : code(code) {
    msg = swoole_strerror(code);
}
}  // namespace swoole

const char *swoole_strerror(int code) {
    if (code < SW_ERROR_BEGIN) {
        return strerror(code);
    }
    /* swstrerror {{{*/
    switch(code) {
    case SW_ERROR_MALLOC_FAIL:
        return "Malloc fail";
    case SW_ERROR_SYSTEM_CALL_FAIL:
        return "System call fail";
    case SW_ERROR_PHP_FATAL_ERROR:
        return "PHP fatal error";
    case SW_ERROR_NAME_TOO_LONG:
        return "Name too long";
    case SW_ERROR_INVALID_PARAMS:
        return "Invalid params";
    case SW_ERROR_QUEUE_FULL:
        return "Queue full";
    case SW_ERROR_OPERATION_NOT_SUPPORT:
        return "Operation not support";
    case SW_ERROR_PROTOCOL_ERROR:
        return "Protocol error";
    case SW_ERROR_WRONG_OPERATION:
        return "Wrong operation";
    case SW_ERROR_FILE_NOT_EXIST:
        return "File not exist";
    case SW_ERROR_FILE_TOO_LARGE:
        return "File too large";
    case SW_ERROR_FILE_EMPTY:
        return "File empty";
    case SW_ERROR_DNSLOOKUP_DUPLICATE_REQUEST:
        return "DNS Lookup duplicate request";
    case SW_ERROR_DNSLOOKUP_RESOLVE_FAILED:
        return "DNS Lookup resolve failed";
    case SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT:
        return "DNS Lookup resolve timeout";
    case SW_ERROR_DNSLOOKUP_UNSUPPORTED:
        return "DNS Lookup unsupported";
    case SW_ERROR_DNSLOOKUP_NO_SERVER:
        return "DNS Lookup no server";
    case SW_ERROR_BAD_IPV6_ADDRESS:
        return "Bad ipv6 address";
    case SW_ERROR_UNREGISTERED_SIGNAL:
        return "Unregistered signal";
    case SW_ERROR_EVENT_SOCKET_REMOVED:
        return "Event socket removed";
    case SW_ERROR_EVENT_SOCKET_INVALID:
        return "Event socket invalid";
    case SW_ERROR_SESSION_CLOSED_BY_SERVER:
        return "Session closed by server";
    case SW_ERROR_SESSION_CLOSED_BY_CLIENT:
        return "Session closed by client";
    case SW_ERROR_SESSION_CLOSING:
        return "Session closing";
    case SW_ERROR_SESSION_CLOSED:
        return "Session closed";
    case SW_ERROR_SESSION_NOT_EXIST:
        return "Session not exist";
    case SW_ERROR_SESSION_INVALID_ID:
        return "Session invalid id";
    case SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA:
        return "Session discard timeout data";
    case SW_ERROR_SESSION_DISCARD_DATA:
        return "Session discard data";
    case SW_ERROR_OUTPUT_BUFFER_OVERFLOW:
        return "Output buffer overflow";
    case SW_ERROR_OUTPUT_SEND_YIELD:
        return "Output send yield";
    case SW_ERROR_SSL_NOT_READY:
        return "SSL not ready";
    case SW_ERROR_SSL_CANNOT_USE_SENFILE:
        return "SSL cannot use senfile";
    case SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE:
        return "SSL empty peer certificate";
    case SW_ERROR_SSL_VERIFY_FAILED:
        return "SSL verify failed";
    case SW_ERROR_SSL_BAD_CLIENT:
        return "SSL bad client";
    case SW_ERROR_SSL_BAD_PROTOCOL:
        return "SSL bad protocol";
    case SW_ERROR_SSL_RESET:
        return "SSL reset";
    case SW_ERROR_SSL_HANDSHAKE_FAILED:
        return "SSL handshake failed";
    case SW_ERROR_PACKAGE_LENGTH_TOO_LARGE:
        return "Package length too large";
    case SW_ERROR_PACKAGE_LENGTH_NOT_FOUND:
        return "Package length not found";
    case SW_ERROR_DATA_LENGTH_TOO_LARGE:
        return "Data length too large";
    case SW_ERROR_PACKAGE_MALFORMED_DATA:
        return "Package malformed data";
    case SW_ERROR_TASK_PACKAGE_TOO_BIG:
        return "Task package too big";
    case SW_ERROR_TASK_DISPATCH_FAIL:
        return "Task dispatch fail";
    case SW_ERROR_TASK_TIMEOUT:
        return "Task timeout";
    case SW_ERROR_HTTP2_STREAM_ID_TOO_BIG:
        return "Http2 stream id too big";
    case SW_ERROR_HTTP2_STREAM_NO_HEADER:
        return "Http2 stream no header";
    case SW_ERROR_HTTP2_STREAM_NOT_FOUND:
        return "Http2 stream not found";
    case SW_ERROR_HTTP2_STREAM_IGNORE:
        return "Http2 stream ignore";
    case SW_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED:
        return "Http2 send control frame failed";
    case SW_ERROR_AIO_BAD_REQUEST:
        return "Aio bad request";
    case SW_ERROR_AIO_CANCELED:
        return "Aio canceled";
    case SW_ERROR_AIO_TIMEOUT:
        return "Aio timeout";
    case SW_ERROR_CLIENT_NO_CONNECTION:
        return "Client no connection";
    case SW_ERROR_SOCKET_CLOSED:
        return "Socket closed";
    case SW_ERROR_SOCKET_POLL_TIMEOUT:
        return "Socket poll timeout";
    case SW_ERROR_SOCKS5_UNSUPPORT_VERSION:
        return "Socks5 unsupport version";
    case SW_ERROR_SOCKS5_UNSUPPORT_METHOD:
        return "Socks5 unsupport method";
    case SW_ERROR_SOCKS5_AUTH_FAILED:
        return "Socks5 auth failed";
    case SW_ERROR_SOCKS5_SERVER_ERROR:
        return "Socks5 server error";
    case SW_ERROR_SOCKS5_HANDSHAKE_FAILED:
        return "Socks5 handshake failed";
    case SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR:
        return "Http proxy handshake error";
    case SW_ERROR_HTTP_INVALID_PROTOCOL:
        return "Http invalid protocol";
    case SW_ERROR_HTTP_PROXY_HANDSHAKE_FAILED:
        return "Http proxy handshake failed";
    case SW_ERROR_HTTP_PROXY_BAD_RESPONSE:
        return "Http proxy bad response";
    case SW_ERROR_WEBSOCKET_BAD_CLIENT:
        return "Websocket bad client";
    case SW_ERROR_WEBSOCKET_BAD_OPCODE:
        return "Websocket bad opcode";
    case SW_ERROR_WEBSOCKET_UNCONNECTED:
        return "Websocket unconnected";
    case SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED:
        return "Websocket handshake failed";
    case SW_ERROR_WEBSOCKET_PACK_FAILED:
        return "Websocket pack failed";
    case SW_ERROR_WEBSOCKET_UNPACK_FAILED:
        return "Websocket unpack failed";
    case SW_ERROR_WEBSOCKET_INCOMPLETE_PACKET:
        return "Websocket incomplete packet";
    case SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT:
        return "Server must created before client";
    case SW_ERROR_SERVER_TOO_MANY_SOCKET:
        return "Server too many socket";
    case SW_ERROR_SERVER_WORKER_TERMINATED:
        return "Server worker terminated";
    case SW_ERROR_SERVER_INVALID_LISTEN_PORT:
        return "Server invalid listen port";
    case SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT:
        return "Server too many listen port";
    case SW_ERROR_SERVER_PIPE_BUFFER_FULL:
        return "Server pipe buffer full";
    case SW_ERROR_SERVER_NO_IDLE_WORKER:
        return "Server no idle worker";
    case SW_ERROR_SERVER_ONLY_START_ONE:
        return "Server only start one";
    case SW_ERROR_SERVER_SEND_IN_MASTER:
        return "Server send in master";
    case SW_ERROR_SERVER_INVALID_REQUEST:
        return "Server invalid request";
    case SW_ERROR_SERVER_CONNECT_FAIL:
        return "Server connect fail";
    case SW_ERROR_SERVER_INVALID_COMMAND:
        return "Server invalid command";
    case SW_ERROR_SERVER_IS_NOT_REGULAR_FILE:
        return "Server is not regular file";
    case SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT:
        return "Server worker exit timeout";
    case SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA:
        return "Server worker abnormal pipe data";
    case SW_ERROR_SERVER_WORKER_UNPROCESSED_DATA:
        return "Server worker unprocessed data";
    case SW_ERROR_CO_OUT_OF_COROUTINE:
        return "Coroutine out of coroutine";
    case SW_ERROR_CO_HAS_BEEN_BOUND:
        return "Coroutine has been bound";
    case SW_ERROR_CO_HAS_BEEN_DISCARDED:
        return "Coroutine has been discarded";
    case SW_ERROR_CO_MUTEX_DOUBLE_UNLOCK:
        return "Coroutine mutex double unlock";
    case SW_ERROR_CO_BLOCK_OBJECT_LOCKED:
        return "Coroutine block object locked";
    case SW_ERROR_CO_BLOCK_OBJECT_WAITING:
        return "Coroutine block object waiting";
    case SW_ERROR_CO_YIELD_FAILED:
        return "Coroutine yield failed";
    case SW_ERROR_CO_GETCONTEXT_FAILED:
        return "Coroutine getcontext failed";
    case SW_ERROR_CO_SWAPCONTEXT_FAILED:
        return "Coroutine swapcontext failed";
    case SW_ERROR_CO_MAKECONTEXT_FAILED:
        return "Coroutine makecontext failed";
    case SW_ERROR_CO_IOCPINIT_FAILED:
        return "Coroutine iocpinit failed";
    case SW_ERROR_CO_PROTECT_STACK_FAILED:
        return "Coroutine protect stack failed";
    case SW_ERROR_CO_STD_THREAD_LINK_ERROR:
        return "Coroutine std thread link error";
    case SW_ERROR_CO_DISABLED_MULTI_THREAD:
        return "Coroutine disabled multi thread";
    case SW_ERROR_CO_CANNOT_CANCEL:
        return "Coroutine cannot cancel";
    case SW_ERROR_CO_NOT_EXISTS:
        return "Coroutine not exists";
    case SW_ERROR_CO_CANCELED:
        return "Coroutine canceled";
    case SW_ERROR_CO_TIMEDOUT:
        return "Coroutine timedout";
    default:
        static char buffer[32];
#ifndef __MACH__
        snprintf(buffer, sizeof(buffer), "Unknown error %d", code);
#else
        snprintf(buffer, sizeof(buffer), "Unknown error: %d", code);
#endif
        return buffer;
    }
    /*}}}*/
}

void swoole_throw_error(int code) {
    throw swoole::Exception(code);
}

void swoole_ignore_error(int code) {
    ignored_errors.insert(code);
}

bool swoole_is_ignored_error(int code) {
    return ignored_errors.find(code) != ignored_errors.end();
}
