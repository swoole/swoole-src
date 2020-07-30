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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swoole_string.h"
#include "swoole_log.h"
#include "swoole_socket.h"
#include "swoole_async.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <mutex>

#if __APPLE__
int swoole_daemon(int nochdir, int noclose) {
    pid_t pid;

    if (!nochdir && chdir("/") != 0) {
        swSysWarn("chdir() failed");
        return -1;
    }

    if (!noclose) {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) {
            swSysWarn("open() failed");
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) {
            close(fd);
            swSysWarn("dup2() failed");
            return -1;
        }

        close(fd);
    }

    pid = swoole_fork(SW_FORK_DAEMON);
    if (pid < 0) {
        swSysWarn("fork() failed");
        return -1;
    }
    if (pid > 0) {
        _exit(0);
    }
    if (setsid() < 0) {
        swSysWarn("setsid() failed");
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

namespace swoole {
namespace async {

void handler_read(Event *event) {
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_SH) < 0) {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }
    while (1) {
        ret = pread(event->fd, event->buf, event->nbytes, event->offset);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0) {
        event->error = errno;
    }
    event->ret = ret;
}

void handler_fread(Event *event) {
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_SH) < 0) {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }
    while (1) {
        ret = read(event->fd, event->buf, event->nbytes);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0) {
        event->error = errno;
    }
    event->ret = ret;
}

void handler_fwrite(Event *event) {
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_EX) < 0) {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        return;
    }
    while (1) {
        ret = write(event->fd, event->buf, event->nbytes);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (event->flags & SW_AIO_WRITE_FSYNC) {
        if (fsync(event->fd) < 0) {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0) {
        event->error = errno;
    }
    event->ret = ret;
}

void handler_fgets(Event *event) {
    if (event->lock && flock(event->fd, LOCK_SH) < 0) {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        event->ret = -1;
        event->error = errno;
        return;
    }

    FILE *file = (FILE *) event->req;
    char *data = fgets((char *) event->buf, event->nbytes, file);
    if (data == nullptr) {
        event->ret = -1;
        event->error = errno;
        event->flags = SW_AIO_EOF;
    }

    if (event->lock && flock(event->fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
}

void handler_read_file(Event *event) {
    swString *data;
    int ret = -1;
    int fd = open((char *) event->req, O_RDONLY);
    if (fd < 0) {
        swSysWarn("open(%s, O_RDONLY) failed", (char *) event->req);
        event->ret = ret;
        event->error = errno;
        return;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        swSysWarn("fstat(%s) failed", (char *) event->req);
    _error:
        close(fd);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG) {
        errno = EISDIR;
        goto _error;
    }

    /**
     * lock
     */
    if (event->lock && flock(fd, LOCK_SH) < 0) {
        swSysWarn("flock(%d, LOCK_SH) failed", event->fd);
        goto _error;
    }
    /**
     * regular file
     */
    if (file_stat.st_size == 0) {
        data = swoole_sync_readfile_eof(fd);
        if (data == nullptr) {
            goto _error;
        }
    } else {
        data = swoole::make_string(file_stat.st_size);
        if (data == nullptr) {
            goto _error;
        }
        data->length = swoole_sync_readfile(fd, data->str, file_stat.st_size);
    }
    event->ret = data->length;
    event->buf = data;
    /**
     * unlock
     */
    if (event->lock && flock(fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    close(fd);
    event->error = 0;
}

void handler_write_file(Event *event) {
    int ret = -1;
    int fd = open((char *) event->req, event->flags, 0644);
    if (fd < 0) {
        swSysWarn("open(%s, %d) failed", (char *) event->req, event->flags);
        event->ret = ret;
        event->error = errno;
        return;
    }
    if (event->lock && flock(fd, LOCK_EX) < 0) {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        event->ret = ret;
        event->error = errno;
        close(fd);
        return;
    }
    size_t written = swoole_sync_writefile(fd, event->buf, event->nbytes);
    if (event->flags & SW_AIO_WRITE_FSYNC) {
        if (fsync(fd) < 0) {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    close(fd);
    event->ret = written;
    event->error = 0;
}

void handler_write(Event *event) {
    int ret = -1;
    if (event->lock && flock(event->fd, LOCK_EX) < 0) {
        swSysWarn("flock(%d, LOCK_EX) failed", event->fd);
        return;
    }
    while (1) {
        ret = pwrite(event->fd, event->buf, event->nbytes, event->offset);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (event->flags & SW_AIO_WRITE_FSYNC) {
        if (fsync(event->fd) < 0) {
            swSysWarn("fsync(%d) failed", event->fd);
        }
    }
    if (event->lock && flock(event->fd, LOCK_UN) < 0) {
        swSysWarn("flock(%d, LOCK_UN) failed", event->fd);
    }
    if (ret < 0) {
        event->error = errno;
    }
    event->ret = ret;
}

void handler_gethostbyname(Event *event) {
    char addr[SW_IP_MAX_LENGTH];
    int ret = swoole::network::gethostbyname(event->flags, (char *) event->buf, addr);
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
    event->ret = ret;
}

void handler_getaddrinfo(Event *event) {
    swoole::network::GetaddrinfoRequest *req = (swoole::network::GetaddrinfoRequest *) event->req;
    event->ret = swoole::network::getaddrinfo(req);
    event->error = req->error;
}

}  // namespace async
}  // namespace swoole
