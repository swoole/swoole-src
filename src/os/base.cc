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

int swoole_get_cpu_affinity(cpu_set_t *set) {
#ifdef __FreeBSD__
    return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(*set), set);
#else
    return sched_getaffinity(getpid(), sizeof(*set), set);
#endif
}
#endif



#if defined(__linux__)
#include <sys/syscall.h> /* syscall(SYS_gettid) */
#elif defined(__FreeBSD__)
#include <pthread_np.h> /* pthread_getthreadid_np() */
#elif defined(__OpenBSD__)
#include <unistd.h> /* getthrid() */
#elif defined(_AIX)
#include <sys/thread.h> /* thread_self() */
#elif defined(__NetBSD__)
#include <lwp.h> /* _lwp_self() */
#elif defined(__CYGWIN__) || defined(WIN32)
#include <windows.h> /* GetCurrentThreadId() */
#endif

long swoole_thread_get_native_id(void) {
#ifdef __APPLE__
    uint64_t native_id;
    (void) pthread_threadid_np(NULL, &native_id);
#elif defined(__linux__)
    pid_t native_id = syscall(SYS_gettid);
#elif defined(__FreeBSD__)
    int native_id = pthread_getthreadid_np();
#elif defined(__OpenBSD__)
    pid_t native_id = getthrid();
#elif defined(_AIX)
    tid_t native_id = thread_self();
#elif defined(__NetBSD__)
    lwpid_t native_id = _lwp_self();
#elif defined(__CYGWIN__) || defined(WIN32)
    DWORD native_id = GetCurrentThreadId();
#endif
    return native_id;
}

bool swoole_thread_set_name(const char *name) {
#if defined(__APPLE__)
    return pthread_setname_np(name) == 0;
#else
    return pthread_setname_np(pthread_self(), name) == 0;
#endif
}

namespace swoole {
namespace async {

void handler_gethostbyname(AsyncEvent *event) {
    char addr[INET6_ADDRSTRLEN];
    auto req = dynamic_cast<GethostbynameRequest *>(event->data.get());
    int ret = network::gethostbyname(req->family, req->name.c_str(), addr);
    sw_memset_zero(req->addr, req->addr_len);

    if (ret < 0) {
        event->error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    } else {
        if (inet_ntop(req->family, addr, req->addr, req->addr_len) == nullptr) {
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
    auto req = dynamic_cast<GetaddrinfoRequest *>(event->data.get());
    event->retval = network::getaddrinfo(req);
    event->error = req->error;
}

}  // namespace async
}  // namespace swoole
