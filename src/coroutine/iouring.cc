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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "swoole_iouring.h"

#ifdef SW_USE_IOURING
using swoole::Iouring;
using swoole::Coroutine;

static sw_inline bool is_no_coro() {
    return SwooleTG.reactor == nullptr || !Coroutine::get_current();
}

int swoole_coroutine_iouring_open(const char *pathname, int flags, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return open(pathname, flags, mode);
    }
    return Iouring::async(SW_IORING_OP_OPENAT, pathname, nullptr, nullptr, flags, mode);
}

int swoole_coroutine_iouring_close_file(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return close(fd);
    }
    return Iouring::async(SW_IORING_OP_CLOSE, fd);
}

ssize_t swoole_coroutine_iouring_read(int sockfd, void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return read(sockfd, buf, count);
    }

    return Iouring::async(SW_IORING_OP_READ, sockfd, count, buf);
}

ssize_t swoole_coroutine_iouring_write(int sockfd, const void *buf, size_t count) {
    if (sw_unlikely(is_no_coro())) {
        return write(sockfd, buf, count);
    }

    return Iouring::async(SW_IORING_OP_WRITE, sockfd, count, nullptr, buf);
}

int swoole_coroutine_iouring_rename(const char *oldpath, const char *newpath) {
    if (sw_unlikely(is_no_coro())) {
        return rename(oldpath, newpath);
    }
    return Iouring::async(SW_IORING_OP_RENAMEAT, oldpath, newpath);
}

int swoole_coroutine_iouring_mkdir(const char *pathname, mode_t mode) {
    if (sw_unlikely(is_no_coro())) {
        return mkdir(pathname, mode);
    }
    return Iouring::async(SW_IORING_OP_MKDIRAT, pathname, nullptr, nullptr, 0, mode);
}

int swoole_coroutine_iouring_unlink(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return unlink(pathname);
    }
    return Iouring::async(SW_IORING_OP_UNLINK_FILE, pathname);
}

void swoole_statx_to_stat(const struct statx *statxbuf, struct stat *statbuf) {
    statbuf->st_dev = (((unsigned int) statxbuf->stx_dev_major) << 8) | (unsigned int) statxbuf->stx_dev_minor;
    statbuf->st_mode = statxbuf->stx_mode;
    statbuf->st_nlink = statxbuf->stx_nlink;
    statbuf->st_uid = statxbuf->stx_uid;
    statbuf->st_gid = statxbuf->stx_gid;
    statbuf->st_rdev = (((unsigned int) statxbuf->stx_rdev_major) << 8) | (unsigned int) statxbuf->stx_rdev_minor;
    statbuf->st_ino = statxbuf->stx_ino;
    statbuf->st_size = statxbuf->stx_size;
    statbuf->st_blksize = statxbuf->stx_blksize;
    statbuf->st_blocks = statxbuf->stx_blocks;
    statbuf->st_atim.tv_sec = statxbuf->stx_atime.tv_sec;
    statbuf->st_atim.tv_nsec = statxbuf->stx_atime.tv_nsec;
    statbuf->st_mtim.tv_sec = statxbuf->stx_mtime.tv_sec;
    statbuf->st_mtim.tv_nsec = statxbuf->stx_mtime.tv_nsec;
    statbuf->st_ctim.tv_sec = statxbuf->stx_ctime.tv_sec;
    statbuf->st_ctim.tv_nsec = statxbuf->stx_ctime.tv_nsec;
}

int swoole_coroutine_iouring_fstat(int fd, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return fstat(fd, statbuf);
    }

    struct statx statxbuf = {};
    int retval = Iouring::async(SW_IORING_OP_FSTAT, fd, 0, nullptr, nullptr, &statxbuf);
    swoole_statx_to_stat(&statxbuf, statbuf);
    return retval;
}

int swoole_coroutine_iouring_stat(const char *path, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return stat(path, statbuf);
    }

    struct statx statxbuf = {};
    int retval = Iouring::async(SW_IORING_OP_LSTAT, path, nullptr, &statxbuf);
    swoole_statx_to_stat(&statxbuf, statbuf);
    return retval;
}

int swoole_coroutine_iouring_lstat(const char *path, struct stat *statbuf) {
    if (sw_unlikely(is_no_coro())) {
        return lstat(path, statbuf);
    }

    struct statx statxbuf = {};
    int retval = Iouring::async(SW_IORING_OP_LSTAT, path, nullptr, &statxbuf);
    swoole_statx_to_stat(&statxbuf, statbuf);
    return retval;
}

int swoole_coroutine_iouring_rmdir(const char *pathname) {
    if (sw_unlikely(is_no_coro())) {
        return rmdir(pathname);
    }

    return Iouring::async(SW_IORING_OP_UNLINK_DIR, pathname);
}

int swoole_coroutine_iouring_fsync(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return fsync(fd);
    }

    return Iouring::async(SW_IORING_OP_FSYNC, fd);
}

int swoole_coroutine_iouring_fdatasync(int fd) {
    if (sw_unlikely(is_no_coro())) {
        return fdatasync(fd);
    }

    return Iouring::async(SW_IORING_OP_FDATASYNC, fd);
}
#endif
