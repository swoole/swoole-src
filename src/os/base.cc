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

#include "swoole_socket.h"
#include "swoole_async.h"
#include "swoole_signal.h"
#include "swoole_api.h"

#include <pwd.h>
#include <grp.h>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__FreeBSD__)
#include <sys/procctl.h>
#endif

#if defined(__APPLE__) && defined(HAVE_CCRANDOMGENERATEBYTES)
#include <Availability.h>
#if (defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000) ||                         \
    (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED >= 80000)
#define OPENSSL_APPLE_CRYPTO_RANDOM 1
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonRandom.h>
#endif
#endif

#include <thread>
#include <sstream>

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
    auto rv = daemon(nochdir, noclose);
    if (rv == 0) {
    	/**
    	 * The daemon function forks the process multiple times, and the pid changes,
    	 * which can lead to PHP assertion failures.
    	 * After PHP 8.5, it is required that the process must call `refresh_memory_manager()` after forking,
    	 * but this does not seem to take into account the invocation of the daemon function.
    	 * If not modified, it will crash during shutdown, and users will think it is a bug in Swoole.
    	 */
        if (swoole_isset_hook(SW_GLOBAL_HOOK_AFTER_FORK)) {
            swoole_call_hook(SW_GLOBAL_HOOK_AFTER_FORK, nullptr);
        }
    }
    return rv;
}
#endif

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#else
static ssize_t getrandom(void *buffer, size_t size, unsigned int __flags) {
#if defined(HAVE_CCRANDOMGENERATEBYTES)
    /*
     * arc4random_buf on macOS uses ccrng_generate internally from which
     * the potential error is silented to respect the portable arc4random_buf interface contract
     */
    if (CCRandomGenerateBytes(buffer, size) == kCCSuccess) {
        return size;
    }
    return -1;
#elif defined(HAVE_ARC4RANDOM)
    arc4random_buf(buffer, size);
    return size;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t read_bytes;
    ssize_t n;
    for (read_bytes = 0; read_bytes < size; read_bytes += (size_t) n) {
        n = read(fd, (char *) buffer + read_bytes, size - read_bytes);
        if (n <= 0) {
            break;
        }
    }

    close(fd);

    return read_bytes;
#endif
}
#endif

#ifdef __ANDROID__
static ssize_t getrandom(char *buf, size_t buflen, uint flags) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, buflen);
    close(fd);
    return n;
}

int pthread_getname_np(pthread_t thread, char *buf, size_t len) {
    sw_snprintf(buf, len, "thread-%lu", (unsigned long) thread);
    return 0;
}
#endif

size_t swoole_random_bytes(char *buf, size_t size) {
    size_t read_bytes = 0;

    while (read_bytes < size) {
        size_t amount_to_read = size - read_bytes;
        ssize_t n = getrandom(buf + read_bytes, amount_to_read, 0);
        if (n == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else {
                break;
            }
        }
        read_bytes += (size_t) n;
    }

    return read_bytes;
}

bool swoole_is_root_user() {
    return geteuid() == 0;
}

void swoole_set_isolation(const std::string &group_, const std::string &user_, const std::string &chroot_) {
    group *_group = nullptr;
    passwd *_passwd = nullptr;
    // get group info
    if (!group_.empty()) {
        _group = getgrnam(group_.c_str());
        if (!_group) {
            swoole_warning("get group [%s] info failed", group_.c_str());
        }
    }
    // get user info
    if (!user_.empty()) {
        _passwd = getpwnam(user_.c_str());
        if (!_passwd) {
            swoole_warning("get user [%s] info failed", user_.c_str());
        }
    }
    // set process group
    if (_group && setgid(_group->gr_gid) < 0) {
        swoole_sys_warning("setgid to [%s] failed", group_.c_str());
    }
    // set process user
    if (_passwd && setuid(_passwd->pw_uid) < 0) {
        swoole_sys_warning("setuid to [%s] failed", user_.c_str());
    }
    // chroot
    if (!chroot_.empty()) {
        if (::chroot(chroot_.c_str()) == 0) {
            if (chdir("/") < 0) {
                swoole_sys_warning("chdir('/') failed");
            }
        } else {
            swoole_sys_warning("chroot('%s') failed", chroot_.c_str());
        }
    }
}

void swoole_set_process_death_signal(int signal) {
#if defined(__linux__)
    prctl(PR_SET_PDEATHSIG, signal);
#elif defined(__FreeBSD__)
    procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &signal);
#else
#warning "no `PDEATHSIG` supports"
#endif
}

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

long swoole_thread_get_native_id() {
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

static bool check_pthread_return_value(int rc) {
    if (rc == 0) {
        return true;
    } else {
        swoole_set_last_error(rc);
        return false;
    }
}

bool swoole_thread_set_name(const char *name) {
#if defined(__APPLE__)
    return check_pthread_return_value(pthread_setname_np(name));
#else
    return check_pthread_return_value(pthread_setname_np(pthread_self(), name));
#endif
}

bool swoole_thread_get_name(char *buf, size_t len) {
    return check_pthread_return_value(pthread_getname_np(pthread_self(), buf, len));
}

std::string swoole_thread_id_to_str(std::thread::id id) {
    std::stringstream ss;
    ss << id;
    return ss.str();
}

namespace swoole {
GethostbynameRequest::GethostbynameRequest(std::string _name, int _family) : name(std::move(_name)), family(_family) {}

GetaddrinfoRequest::GetaddrinfoRequest(
    std::string _hostname, int _family, int _socktype, int _protocol, std::string _service)
    : hostname(std::move(_hostname)), service(std::move(_service)) {
    family = _family;
    socktype = _socktype;
    protocol = _protocol;
    count = 0;
    error = 0;
}

namespace async {
void handler_gethostbyname(AsyncEvent *event) {
    auto req = dynamic_cast<GethostbynameRequest *>(event->data.get());
    event->retval = network::gethostbyname(req);
    if (event->retval < 0) {
        event->error = swoole_get_last_error();
    } else {
        event->error = 0;
    }
}

void handler_getaddrinfo(AsyncEvent *event) {
    auto req = dynamic_cast<GetaddrinfoRequest *>(event->data.get());
    event->retval = network::getaddrinfo(req);
    event->error = req->error;
}
}  // namespace async
}  // namespace swoole
