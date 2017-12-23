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

#ifndef SW_ERRNO_H_
#define SW_ERRNO_H_

enum swErrorCode
{
    /**
     * common error
     */
    SW_ERROR_MALLOC_FAIL = 501,
    SW_ERROR_SYSTEM_CALL_FAIL,
    SW_ERROR_PHP_FATAL_ERROR,
    SW_ERROR_NAME_TOO_LONG,
    SW_ERROR_INVALID_PARAMS,

    SW_ERROR_FILE_NOT_EXIST = 700,
    SW_ERROR_FILE_TOO_LARGE,
    SW_ERROR_FILE_EMPTY,
    SW_ERROR_DNSLOOKUP_DUPLICATE_REQUEST,
    SW_ERROR_DNSLOOKUP_RESOLVE_FAILED,

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
    SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
    SW_ERROR_SSL_NOT_READY,
    SW_ERROR_SSL_CANNOT_USE_SENFILE,
    SW_ERROR_SSL_EMPTY_PEER_CERTIFICATE,
    SW_ERROR_SSL_VEFIRY_FAILED,
    SW_ERROR_SSL_BAD_CLIENT,
    SW_ERROR_SSL_BAD_PROTOCOL,

    SW_ERROR_PACKAGE_LENGTH_TOO_LARGE = 1201,
    SW_ERROR_DATA_LENGTH_TOO_LARGE,

    /**
     * task error
     */
    SW_ERROR_TASK_PACKAGE_TOO_BIG = 2001,
    SW_ERROR_TASK_DISPATCH_FAIL,

    /**
     * http2 protocol error
     */
    SW_ERROR_HTTP2_STREAM_ID_TOO_BIG = 3001,
    SW_ERROR_HTTP2_STREAM_NO_HEADER,

    SW_ERROR_SOCKS5_UNSUPPORT_VERSION = 7001,
    SW_ERROR_SOCKS5_UNSUPPORT_METHOD,
    SW_ERROR_SOCKS5_AUTH_FAILED,
    SW_ERROR_SOCKS5_SERVER_ERROR,
    
    SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR = 8001,
    SW_ERROR_HTTP_INVALID_PROTOCOL,

    SW_ERROR_WEBSOCKET_BAD_CLIENT = 8501,
    SW_ERROR_WEBSOCKET_BAD_OPCODE,
    SW_ERROR_WEBSOCKET_UNCONNECTED,
    SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED,

    /**
     * server global error
     */
    SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT = 9001,
    SW_ERROR_SERVER_TOO_MANY_SOCKET,
    SW_ERROR_SERVER_WORKER_TERMINATED,
    SW_ERROR_SERVER_INVALID_LISTEN_PORT,
    SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT,
    SW_ERROR_SERVER_PIPE_BUFFER_FULL,

    SW_ERROR_SERVER_ONLY_START_ONE,

    /**
     * Process exit timeout, forced to end.
     */
    SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT,

};

#endif /* SW_ERRNO_H_ */
