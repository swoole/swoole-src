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
#include "swoole_file.h"
#include "swoole_coroutine_c_api.h"

namespace swoole {
AsyncFile::AsyncFile(const std::string &path, int flags, int mode) {
    open(path, flags, mode);
}

AsyncFile::~AsyncFile() {
    close();

    fd = -1;
    flags_ = 0;
    mode_ = 0;
    path_ = "";
}

bool AsyncFile::open(const std::string &path, int flags, mode_t mode) {
    close();

    flags_ = flags;
    mode_ = mode;
    path_ = path;

#ifdef SW_USE_IOURING
    fd = swoole_coroutine_iouring_open(path.c_str(), flags, mode);
#else
    fd = swoole_coroutine_open(path.c_str(), flags, mode);
#endif
    return fd > 0;
}

bool AsyncFile::close() {
    if (sw_unlikely(fd == -1)) {
        return false;
    }

#ifdef SW_USE_IOURING
    return swoole_coroutine_iouring_close_file(fd) == 0;
#else
    return swoole_coroutine_close_file(fd) == 0;
#endif
}

ssize_t AsyncFile::read(void *buf, size_t count) const {
#ifdef SW_USE_IOURING
    return swoole_coroutine_iouring_read(fd, buf, count);
#else
    return swoole_coroutine_read(fd, buf, count);
#endif
}

ssize_t AsyncFile::write(void *buf, size_t count) const {
#ifdef SW_USE_IOURING
    return swoole_coroutine_iouring_write(fd, buf, count);
#else
    return swoole_coroutine_write(fd, buf, count);
#endif
}

bool AsyncFile::sync() const {
#ifdef SW_USE_IOURING
    return swoole_coroutine_iouring_fsync(fd) == 0;
#else
    return swoole_coroutine_fsync(fd) == 0;
#endif
}

bool AsyncFile::truncate(off_t length) const {
#if defined(SW_USE_IOURING) && defined(HAVE_IOURING_FTRUNCATE)
    return swoole_coroutine_iouring_ftruncate(fd, length) == 0;
#else
    return swoole_coroutine_ftruncate(fd, length) == 0;
#endif
}

bool AsyncFile::stat(FileStatus *statbuf) const {
#if defined(SW_USE_IOURING) && defined(HAVE_IOURING_STATX)
    return swoole_coroutine_iouring_fstat(fd, statbuf) == 0;
#else
    return swoole_coroutine_fstat(fd, statbuf) == 0;
#endif
}

off_t AsyncFile::get_offset() const {
    return swoole_coroutine_lseek(fd, 0, SEEK_CUR);
}

off_t AsyncFile::set_offset(off_t offset) const {
    return swoole_coroutine_lseek(fd, offset, SEEK_SET);
}
}  // namespace swoole
