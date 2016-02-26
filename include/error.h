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
    SW_ERROR_MALLOC_FAIL                         = 501,
    SW_ERROR_SYSTEM_CALL_FAIL                    = 502,
    /**
     * master process
     */
    SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT   = 9001,
    SW_ERROR_SERVER_TOO_MANY_SOCKET              = 9002,
    /**
     * connection error
     */
    SW_ERROR_SESSION_CLOSED_BY_SERVER            = 1001,
    SW_ERROR_SESSION_CLOSED_BY_CLIENT,
    SW_ERROR_SESSION_CLOSING,
    SW_ERROR_SESSION_CLOSED,
    SW_ERROR_SESSION_NO_EXIST,
    SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
    SW_ERROR_SSL_NOT_READY,
    SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA,
};

#endif /* SW_ERRNO_H_ */
