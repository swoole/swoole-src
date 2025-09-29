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
}

bool AsyncFile::open(const std::string &path, int flags, mode_t mode) {
    close();

    flags_ = flags;
    mode_ = mode;
    path_ = path;
    fd = swoole_coroutine_open(path.c_str(), flags, mode);
    return fd > 0;
}

bool AsyncFile::close() {
    if (sw_unlikely(fd == -1)) {
        return false;
    }

    return swoole_coroutine_close(fd) == 0;
}

ssize_t AsyncFile::read(void *buf, size_t count) const {
    return swoole_coroutine_read(fd, buf, count);
}

ssize_t AsyncFile::write(const void *buf, size_t count) const {
    return swoole_coroutine_write(fd, buf, count);
}

bool AsyncFile::sync() const {
    return swoole_coroutine_fsync(fd) == 0;
}

bool AsyncFile::truncate(off_t length) const {
    return swoole_coroutine_ftruncate(fd, length) == 0;
}

bool AsyncFile::stat(FileStatus *statbuf) const {
    return swoole_coroutine_fstat(fd, statbuf) == 0;
}

off_t AsyncFile::get_offset() const {
    return swoole_coroutine_lseek(fd, 0, SEEK_CUR);
}

off_t AsyncFile::set_offset(off_t offset) const {
    return swoole_coroutine_lseek(fd, offset, SEEK_SET);
}
}  // namespace swoole
