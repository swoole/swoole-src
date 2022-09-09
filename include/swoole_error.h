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

#pragma once

enum swErrorCode {
    /**
     * Prevent repetition with errno [syscall error]
     */
    SW_ERROR_BEGIN = 500,

    /**
     * common error
     */
    SW_ERROR_MALLOC_FAIL = 501,
    SW_ERROR_SYSTEM_CALL_FAIL,
    SW_ERROR_PHP_FATAL_ERROR,
    SW_ERROR_NAME_TOO_LONG,
    SW_ERROR_INVALID_PARAMS,
    SW_ERROR_QUEUE_FULL,
    SW_ERROR_OPERATION_NOT_SUPPORT,
    SW_ERROR_PROTOCOL_ERROR,
    SW_ERROR_WRONG_OPERATION,

    SW_ERROR_FILE_NOT_EXIST = 700,
    SW_ERROR_FILE_TOO_LARGE,
    SW_ERROR_FILE_EMPTY,

    SW_ERROR_DNSLOOKUP_DUPLICATE_REQUEST = 710,
    SW_ERROR_DNSLOOKUP_RESOLVE_FAILED,
    SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT,
    SW_ERROR_DNSLOOKUP_UNSUPPORTED,
    SW_ERROR_DNSLOOKUP_NO_SERVER,

    SW_ERROR_BAD_IPV6_ADDRESS = 720,
    SW_ERROR_UNREGISTERED_SIGNAL,

    // EventLoop
    SW_ERROR_EVENT_SOCKET_REMOVED = 800,
    SW_ERROR_EVENT_SOCKET_INVALID,

    /**
     * connection error
     */
    SW_ERROR_SESSION_CLOSED_BY_SERVER = 1001,
    SW_ERROR_SESSION_CLOSED_BY_CLIENT,
    SW_ERROR_SESSION_CLOSING,
    SW_ERROR_SESSION_CLOSED,
    SW_ERROR_SESSION_NOT_EXIST,
    SW_ERROR_SESSION_INVALID_ID,
    SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
    SW_ERROR_SESSION_DISCARD_DATA,
    SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
    SW_ERROR_OUTPUT_SEND_YIELD,
    SW_ERROR_SSL_NOT_READY,
    SW_ERROR_SSL_CANNOT_USE_SENFILE,
    SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE,
    SW_ERROR_SSL_VERIFY_FAILED,
    SW_ERROR_SSL_BAD_CLIENT,
    SW_ERROR_SSL_BAD_PROTOCOL,
    SW_ERROR_SSL_RESET,
    SW_ERROR_SSL_HANDSHAKE_FAILED,

    SW_ERROR_PACKAGE_LENGTH_TOO_LARGE = 1201,
    SW_ERROR_PACKAGE_LENGTH_NOT_FOUND,
    SW_ERROR_DATA_LENGTH_TOO_LARGE,
    SW_ERROR_PACKAGE_MALFORMED_DATA,

    /**
     * task error
     */
    SW_ERROR_TASK_PACKAGE_TOO_BIG = 2001,
    SW_ERROR_TASK_DISPATCH_FAIL,
    SW_ERROR_TASK_TIMEOUT,

    /**
     * http2 protocol error
     */
    SW_ERROR_HTTP2_STREAM_ID_TOO_BIG = 3001,
    SW_ERROR_HTTP2_STREAM_NO_HEADER,
    SW_ERROR_HTTP2_STREAM_NOT_FOUND,
    SW_ERROR_HTTP2_STREAM_IGNORE,
    SW_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED,

    /**
     * AIO
     */
    SW_ERROR_AIO_BAD_REQUEST = 4001,
    SW_ERROR_AIO_CANCELED,
    SW_ERROR_AIO_TIMEOUT,

    /**
     * Client
     */
    SW_ERROR_CLIENT_NO_CONNECTION = 5001,

    /**
     * Socket
     */
    SW_ERROR_SOCKET_CLOSED = 6001,
    SW_ERROR_SOCKET_POLL_TIMEOUT,

    /**
     * Proxy
     */
    SW_ERROR_SOCKS5_UNSUPPORT_VERSION = 7001,
    SW_ERROR_SOCKS5_UNSUPPORT_METHOD,
    SW_ERROR_SOCKS5_AUTH_FAILED,
    SW_ERROR_SOCKS5_SERVER_ERROR,
    SW_ERROR_SOCKS5_HANDSHAKE_FAILED,

    SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR = 7101,
    SW_ERROR_HTTP_INVALID_PROTOCOL,
    SW_ERROR_HTTP_PROXY_HANDSHAKE_FAILED,
    SW_ERROR_HTTP_PROXY_BAD_RESPONSE,

    SW_ERROR_WEBSOCKET_BAD_CLIENT = 8501,
    SW_ERROR_WEBSOCKET_BAD_OPCODE,
    SW_ERROR_WEBSOCKET_UNCONNECTED,
    SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED,
    SW_ERROR_WEBSOCKET_PACK_FAILED,
    SW_ERROR_WEBSOCKET_UNPACK_FAILED,
    SW_ERROR_WEBSOCKET_INCOMPLETE_PACKET,

    /**
     * server global error
     */
    SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT = 9001,
    SW_ERROR_SERVER_TOO_MANY_SOCKET,
    SW_ERROR_SERVER_WORKER_TERMINATED,
    SW_ERROR_SERVER_INVALID_LISTEN_PORT,
    SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT,
    SW_ERROR_SERVER_PIPE_BUFFER_FULL,
    SW_ERROR_SERVER_NO_IDLE_WORKER,
    SW_ERROR_SERVER_ONLY_START_ONE,
    SW_ERROR_SERVER_SEND_IN_MASTER,
    SW_ERROR_SERVER_INVALID_REQUEST,
    SW_ERROR_SERVER_CONNECT_FAIL,
    SW_ERROR_SERVER_INVALID_COMMAND,
    SW_ERROR_SERVER_IS_NOT_REGULAR_FILE,

    /**
     * Process exit timeout, forced to end.
     */
    SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT = 9101,
    SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA,
    SW_ERROR_SERVER_WORKER_UNPROCESSED_DATA,

    /**
     * Coroutine
     */
    SW_ERROR_CO_OUT_OF_COROUTINE = 10001,
    SW_ERROR_CO_HAS_BEEN_BOUND,
    SW_ERROR_CO_HAS_BEEN_DISCARDED,

    SW_ERROR_CO_MUTEX_DOUBLE_UNLOCK,
    SW_ERROR_CO_BLOCK_OBJECT_LOCKED,
    SW_ERROR_CO_BLOCK_OBJECT_WAITING,
    SW_ERROR_CO_YIELD_FAILED,
    SW_ERROR_CO_GETCONTEXT_FAILED,
    SW_ERROR_CO_SWAPCONTEXT_FAILED,
    SW_ERROR_CO_MAKECONTEXT_FAILED,

    SW_ERROR_CO_IOCPINIT_FAILED,
    SW_ERROR_CO_PROTECT_STACK_FAILED,
    SW_ERROR_CO_STD_THREAD_LINK_ERROR,
    SW_ERROR_CO_DISABLED_MULTI_THREAD,

    SW_ERROR_CO_CANNOT_CANCEL,
    SW_ERROR_CO_NOT_EXISTS,
    SW_ERROR_CO_CANCELED,
    SW_ERROR_CO_TIMEDOUT,

    SW_ERROR_END
};

namespace swoole {
class Exception {
  public:
    int code;
    const char *msg;

    Exception(int code) throw();
};
}  // namespace swoole
