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

#include "swoole_coroutine_socket.h"

#include <memory>

using CoSocket = swoole::coroutine::Socket;
using NetSocket = swoole::network::Socket;

#ifdef SW_USE_URING_SOCKET
#include "swoole_uring_socket.h"
using swoole::coroutine::UringSocket;
using SocketImpl = UringSocket;
#else
using SocketImpl = CoSocket;
#endif

std::shared_ptr<SocketImpl> swoole_coroutine_get_socket_object(int sockfd);
std::shared_ptr<SocketImpl> swoole_coroutine_get_socket_object_ex(int sockfd);
