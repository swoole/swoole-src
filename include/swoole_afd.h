/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
*/

#pragma once

#if defined(_WIN32)

#include "swoole.h"

#include <winsock2.h>
#include <windows.h>

namespace swoole {
namespace afd {

static constexpr DWORD IOCTL_POLL = 0x00012024;

static constexpr ULONG POLL_RECEIVE = 0x0001;
static constexpr ULONG POLL_RECEIVE_EXPEDITED = 0x0002;
static constexpr ULONG POLL_SEND = 0x0004;
static constexpr ULONG POLL_DISCONNECT = 0x0008;
static constexpr ULONG POLL_ABORT = 0x0010;
static constexpr ULONG POLL_LOCAL_CLOSE = 0x0020;
static constexpr ULONG POLL_CONNECT_FAIL = 0x0100;

static constexpr ULONG POLL_ERROR_EVENTS = POLL_CONNECT_FAIL | POLL_ABORT | POLL_LOCAL_CLOSE;
static constexpr ULONG POLL_CLOSE_EVENTS = POLL_DISCONNECT | POLL_ABORT | POLL_LOCAL_CLOSE;

struct PollHandleInfo {
    HANDLE handle;
    ULONG events;
    LONG status;
};

struct PollInfo {
    LARGE_INTEGER timeout;
    ULONG number_of_handles;
    ULONG exclusive;
    PollHandleInfo handles[1];
};

static inline void init_poll_info(PollInfo *info, swSocketFd fd, ULONG events) {
    info->timeout.QuadPart = INT64_MAX;
    info->number_of_handles = 1;
    info->exclusive = TRUE;
    info->handles[0].handle = reinterpret_cast<HANDLE>(fd);
    info->handles[0].events = events;
    info->handles[0].status = 0;
}

}  // namespace afd
}  // namespace swoole

#endif
