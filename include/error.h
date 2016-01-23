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
     * reactor thread
     */
    SW_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT   = 9001,
    /**
     * server event worker
     */
    SW_ERROR_SERVER_WORKER_CLOSING               = 8001,
    SW_ERROR_SESSION_CLOSED_BY_SERVER            = 1001,
    SW_ERROR_SESSION_CLOSED_BY_CLIENT            = 1002,
    SW_ERROR_OUTPUT_BUFFER_OVERFLOW              = 1003,
};

#endif /* SW_ERRNO_H_ */
