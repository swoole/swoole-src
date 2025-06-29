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

#include "swoole_file.h"
#include "swoole_coroutine_c_api.h"

int swoole_tmpfile(char *filename) {
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (sw_likely(tmp_fd > 0)) {
        return tmp_fd;
    }
    swoole_sys_warning("mkstemp('%s') failed", filename);
    return SW_ERR;
}

namespace swoole {

ssize_t file_get_size(FILE *fp) {
    fflush(fp);
    return file_get_size(fileno(fp));
}

ssize_t file_get_size(const std::string &filename) {
    File file(filename, File::READ);
    if (sw_likely(file.ready())) {
        return file.get_size();
    }
    swoole_set_last_error(errno);
    return -1;
}

ssize_t file_get_size(int fd) {
    FileStatus file_stat;
    if (sw_likely(fstat(fd, &file_stat) > 0 && S_ISREG(file_stat.st_mode))) {
        return file_stat.st_size;
    }
    swoole_set_last_error(errno);
    return -1;
}

std::shared_ptr<String> file_get_contents(const std::string &filename) {
    File fp(filename, O_RDONLY);
    if (!fp.ready()) {
        swoole_sys_warning("open('%s') failed", filename.c_str());
        return nullptr;
    }

    ssize_t filesize = fp.get_size();
    if (filesize < 0) {
        return nullptr;
    } else if (filesize == 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "file[%s] is empty", filename.c_str());
        return nullptr;
    } else if (filesize > SwooleG.max_file_content) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "file[%s] is too large", filename.c_str());
        return nullptr;
    }

    std::shared_ptr<String> content = std::make_shared<String>(filesize + 1);
    ssize_t read_bytes = fp.read_all(content->str, filesize);
    content->length = read_bytes;
    content->str[read_bytes] = '\0';
    return content;
}

bool file_put_contents(const std::string &filename, const char *content, size_t length) {
    if (length == 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_EMPTY, "content is empty");
        return false;
    }
    if (length > SwooleG.max_file_content) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "content is too large");
        return false;
    }
    File file(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (sw_likely(file.ready())) {
        return file.write_all(content, length);
    }

    swoole_sys_warning("open('%s') failed", filename.c_str());
    return false;
}

bool file_exists(const std::string &filename) {
    return access(filename.c_str(), F_OK) == 0;
}

File make_tmpfile() {
    char *tmpfile = sw_tg_buffer()->str;
    size_t l = swoole_strlcpy(tmpfile, SwooleG.task_tmpfile.c_str(), SW_TASK_TMP_PATH_SIZE);
    int tmp_fd = swoole_tmpfile(tmpfile);
    if (sw_likely(tmp_fd > 0)) {
        return {tmp_fd, std::string(tmpfile, l)};
    }

    return File(-1);
}

File::File(const std::string &path, int oflags) {
    fd_ = -1;
    open(path, oflags);
}

File::File(const std::string &path, int oflags, int mode) {
    fd_ = -1;
    open(path, oflags, mode);
}

bool File::open(const std::string &path, int oflags, int mode) {
    if (fd_ != -1) {
        ::close(fd_);
    }
    if (oflags & CREATE) {
        fd_ = ::open(path.c_str(), oflags, mode == 0 ? 0644 : mode);
    } else {
        fd_ = ::open(path.c_str(), oflags);
    }
    path_ = path;
    flags_ = oflags;
    return ready();
}

bool File::close() {
    if (fd_ == -1) {
        return false;
    }
    int tmp_fd = fd_;
    fd_ = -1;
    return ::close(tmp_fd) == 0;
}

bool File::stat(FileStatus *_stat) const {
    if (::fstat(fd_, _stat) < 0) {
        swoole_sys_warning("fstat() failed");
        return false;
    }
    return true;
}

File::~File() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

static swReturnCode catch_fs_error(const ssize_t rv, const int error) {
    if (rv == 0) {
        return SW_CLOSE;
    }
    if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK) {
        return SW_CONTINUE;
    }
    return SW_ERROR;
}

size_t File::write_all(const void *data, size_t len) const {
    size_t written_bytes = 0;
    while (written_bytes < len) {
        ssize_t n;
        if (flags_ & APPEND) {
            n = write((char *) data + written_bytes, len - written_bytes);
        } else {
            n = pwrite((char *) data + written_bytes, len - written_bytes, written_bytes);
        }
        if (n > 0) {
            written_bytes += n;
        } else {
            const auto rc = catch_fs_error(n, errno);
            if (rc == SW_ERROR) {
                swoole_sys_warning("pwrite(%d, %p, %lu, %lu) failed", fd_, data, len - written_bytes, written_bytes);
            } else if (rc == SW_CONTINUE) {
                continue;
            }
            break;
        }
    }
    return written_bytes;
}

size_t File::read_all(void *buf, size_t len) const {
    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t n = pread((char *) buf + read_bytes, len - read_bytes, read_bytes);
        if (n > 0) {
            read_bytes += n;
        } else {
            const auto rc = catch_fs_error(n, errno);
            if (rc == SW_ERROR) {
                swoole_sys_warning("pread(%d, %p, %lu, %lu) failed", fd_, buf, len - read_bytes, read_bytes);
            } else if (rc == SW_CONTINUE) {
                continue;
            }
            break;
        }
    }
    return read_bytes;
}

ssize_t File::read_line(void *__buf, size_t __n) const {
    char *buf = (char *) __buf;
    auto offset = get_offset();
    ssize_t read_bytes = read(buf, __n - 1);
    if (read_bytes <= 0) {
        return read_bytes;
    }
    for (ssize_t i = 0; i < read_bytes; ++i) {
        if (buf[i] == '\0' || buf[i] == '\n') {
            buf[i + 1] = '\0';
            set_offset(offset + i + 1);
            return i + 1;
        }
    }
    buf[read_bytes] = '\0';
    set_offset(offset + read_bytes + 1);
    return read_bytes;
}

std::shared_ptr<String> File::read_content() const {
    ssize_t n = 0;
    auto data = std::make_shared<String>(SW_BUFFER_SIZE_STD);
    while (true) {
        n = read(data->str + data->length, data->size - data->length);
        if (n <= 0) {
            break;
        }
        if (!data->grow((size_t) n)) {
            break;
        }
    }
    return data;
}

AsyncFile::AsyncFile(const std::string &path, int flags, int mode) {
    open(path.c_str(), flags, mode);
}

AsyncFile::~AsyncFile() {
    if (sw_likely(fd != -1)) {
        close();
    }
    fd = -1;
}

bool AsyncFile::open(const std::string &path, int flags, mode_t mode) {
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
#if defined(SW_USE_IOURING)
    return swoole_coroutine_iouring_lseek(fd, 0, SEEK_CUR);
#else
    return swoole_coroutine_lseek(fd, 0, SEEK_CUR);
#endif
}

off_t AsyncFile::set_offset(off_t offset) const {
#if defined(SW_USE_IOURING)
    return swoole_coroutine_iouring_lseek(fd, offset, SEEK_SET);
#else
    return swoole_coroutine_lseek(fd, offset, SEEK_SET);
#endif
}

}  // namespace swoole
