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
};

}
