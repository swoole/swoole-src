/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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
#include "swoole_socket.h"
#include "swoole_async.h"

#include <arpa/inet.h>

#if __APPLE__
int swoole_daemon(int nochdir, int noclose) {
    pid_t pid;

    if (!nochdir && chdir("/") != 0) {
        swoole_sys_warning("chdir() failed");
        return -1;
    }

    if (!noclose) {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) {
            swoole_sys_warning("open() failed");
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) {
            close(fd);
            swoole_sys_warning("dup2() failed");
            return -1;
        }

        close(fd);
    }

    pid = swoole_fork(SW_FORK_DAEMON);
    if (pid < 0) {
        swoole_sys_warning("fork() failed");
        return -1;
    }
    if (pid > 0) {
        _exit(0);
    }
    if (setsid() < 0) {
        swoole_sys_warning("setsid() failed");
        return -1;
    }
    return 0;
}
#else
int swoole_daemon(int nochdir, int noclose) {
    if (swoole_fork(SW_FORK_PRECHECK) < 0) {
        return -1;
    }
    return daemon(nochdir, noclose);
}
#endif

#ifdef HAVE_CPU_AFFINITY
int swoole_set_cpu_affinity(cpu_set_t *set) {
#ifdef __FreeBSD__
    return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(*set), set);
#else
    return sched_setaffinity(getpid(), sizeof(*set), set);
#endif
}
#endif

namespace swoole {
namespace async {

void handler_gethostbyname(AsyncEvent *event) {
    char addr[SW_IP_MAX_LENGTH];
    int ret = network::gethostbyname(event->flags, (char *) event->buf, addr);
    sw_memset_zero(event->buf, event->nbytes);

    if (ret < 0) {
        event->error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    } else {
        if (inet_ntop(event->flags, addr, (char *) event->buf, event->nbytes) == nullptr) {
            ret = -1;
            event->error = SW_ERROR_BAD_IPV6_ADDRESS;
        } else {
            event->error = 0;
            ret = 0;
        }
    }
    event->retval = ret;
}

void handler_getaddrinfo(AsyncEvent *event) {
    network::GetaddrinfoRequest *req = (network::GetaddrinfoRequest *) event->req;
    event->retval = network::getaddrinfo(req);
    event->error = req->error;
}

}  // namespace async
}  // namespace swoole
