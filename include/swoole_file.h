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

#include "swoole.h"
#include "swoole_string.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace swoole {

ssize_t file_get_size(FILE *fp);
ssize_t file_get_size(int fd);
ssize_t file_get_size(const std::string &filename);
std::shared_ptr<String> file_get_contents(const std::string &filename);
bool file_put_contents(const std::string &filename, const char *content, size_t length);

typedef struct stat FileStatus;

class File {
  private:
    int fd_;
    int flags_;
    std::string path_;

  public:
    enum Flag {
        READ = O_RDONLY,
        WRITE = O_WRONLY,
        RW = O_RDWR,
        CREATE = O_CREAT,
        EXCL = O_EXCL,
        APPEND = O_APPEND,
    };

    explicit File(int fd) {
        fd_ = fd;
        flags_ = 0;
    }

    File(int fd, const std::string &path) {
        fd_ = fd;
        path_ = path;
        flags_ = 0;
    }

    File(const std::string &path, int oflags) {
        fd_ = ::open(path.c_str(), oflags);
        path_ = path;
        flags_ = oflags;
    }

    File(const std::string &path, int oflags, int mode) {
        fd_ = ::open(path.c_str(), oflags, mode);
        path_ = path;
        flags_ = oflags;
    }

    ~File() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    bool ready() {
        return fd_ != -1;
    }

    ssize_t write(const void *__buf, size_t __n) const {
        return ::write(fd_, __buf, __n);
    }

    ssize_t read(void *__buf, size_t __n) const {
        return ::read(fd_, __buf, __n);
    }

    ssize_t pwrite(const void *__buf, size_t __n, off_t __offset) const {
        return ::pwrite(fd_, __buf, __n, __offset);
    }

    ssize_t pread(void *__buf, size_t __n, off_t __offset) const {
        return ::pread(fd_, __buf, __n, __offset);
    }

    size_t write_all(const void *__buf, size_t __n);
    size_t read_all(void *__buf, size_t __n);

    std::shared_ptr<String> read_content();

    bool stat(FileStatus *_stat) const {
        if (::fstat(fd_, _stat) < 0) {
            swoole_sys_warning("fstat() failed");
            return false;
        } else {
            return true;
        }
    }

    bool sync() {
        return ::fsync(fd_) == 0;
    }

    bool truncate(size_t size) {
        return ::ftruncate(fd_, size) == 0;
    }

    off_t set_offest(off_t offset) {
        return lseek(fd_, offset, SEEK_SET);
    }

    off_t get_offset() {
        return lseek(fd_, 0, SEEK_CUR);
    }

    bool lock(int operation) {
        return ::flock(fd_, operation) == 0;
    }

    bool unlock() {
        return ::flock(fd_, LOCK_UN) == 0;
    }

    ssize_t get_size() {
        return file_get_size(fd_);
    }

    bool close() {
        if (fd_ == -1) {
            return false;
        }
        int tmp_fd = fd_;
        fd_ = -1;
        return ::close(tmp_fd) == 0;
    }

    void release() {
        fd_ = -1;
    }

    int get_fd() {
        return fd_;
    }

    const std::string &get_path() {
        return path_;
    }

    static bool exists(const std::string &file) {
        return access(file.c_str(), R_OK) == 0;
    }
};

File make_tmpfile();

}  // namespace swoole
