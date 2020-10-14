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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_string.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

size_t swoole_sync_writefile(int fd, const void *data, size_t len);
size_t swoole_sync_readfile(int fd, void *buf, size_t len);
swoole::String *swoole_sync_readfile_eof(int fd);
ssize_t swoole_file_get_size(FILE *fp);
ssize_t swoole_file_get_size(int fd);
ssize_t swoole_file_get_size(const std::string &filename);
std::shared_ptr<swoole::String> swoole_file_get_contents(const std::string &filename);
bool swoole_file_put_contents(const char *filename, const char *content, size_t length);

namespace swoole {

typedef struct stat FileStatus;

class File {
 private:
    int fd_;

 public:
    enum Flag {
        READ = O_RDONLY,
        WRITE = O_WRONLY,
        RW = O_RDWR,
        CREATE = O_CREAT,
        EXCL = O_EXCL,
        APPEND = O_APPEND,
    };

    File(int fd) {
        fd_ = fd;
    }

    File(const std::string &file, int oflags) {
        fd_ = ::open(file.c_str(), oflags);
    }

    File(const std::string &file, int oflags, int mode) {
        fd_ = ::open(file.c_str(), oflags, mode);
    }

    ~File() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    bool ready() {
        return fd_ != -1;
    }

    ssize_t write(const void *__buf, size_t __n) {
        return ::write(fd_, __buf, __n);
    }


    ssize_t read(void *__buf, size_t __n) {
        return ::read(fd_, __buf, __n);
    }

    bool stat(FileStatus *_stat) {
        if ( ::fstat(fd_, _stat) < 0) {
            swSysWarn("fstat() failed");
            return false;
        } else {
            return true;
        }
    }

    bool truncate(size_t size) {
        return ::ftruncate(fd_, size);
    }

    off_t set_offest(off_t offset) {
        return lseek(fd_, offset, SEEK_SET);
    }

    off_t get_offset() {
        return lseek(fd_, 0, SEEK_CUR);
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

    static bool exists(const std::string &file) {
        return access(file.c_str(), R_OK) == 0;
    }
};

}
