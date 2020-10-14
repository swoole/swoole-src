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

#include "swoole_file.h"

int swoole_tmpfile(char *filename) {
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0) {
        swSysWarn("mkstemp(%s) failed", filename);
        return SW_ERR;
    } else {
        return tmp_fd;
    }
}

namespace swoole {

ssize_t file_get_size(FILE *fp) {
    fflush(fp);
    return file_get_size(fileno(fp));
}

ssize_t file_get_size(const std::string &filename) {
    File file(filename, File::READ);
    if (!file.ready()) {
        swoole_set_last_error(errno);
        return -1;
    }
    return file.get_size();
}

ssize_t file_get_size(int fd) {
    FileStatus file_stat;
    if (fstat(fd, &file_stat) < 0) {
        swoole_set_last_error(errno);
        return -1;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG) {
        swoole_set_last_error(EISDIR);
        return -1;
    }
    return file_stat.st_size;
}

std::shared_ptr<String> file_get_contents(const std::string &filename) {
    File fp(filename, O_RDONLY);
    if (!fp.ready()) {
        swSysWarn("open(%s) failed", filename.c_str());
        return nullptr;
    }

    ssize_t filesize = fp.get_size();
    if (filesize < 0) {
        return nullptr;
    } else if (filesize == 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "file[%s] is empty", filename.c_str());
        return nullptr;
    } else if (filesize > SW_MAX_FILE_CONTENT) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "file[%s] is too large", filename.c_str());
        return nullptr;
    }

    std::shared_ptr<String> content = std::make_shared<String>(filesize + 1);
    ssize_t read_bytes = fp.read_all(content->str, filesize);
    content->length = read_bytes;
    content->str[read_bytes] = '\0';
    return content;
}

File make_tmpfile() {
    char *tmpfile = SwooleTG.buffer_stack->str;
    size_t l = swoole_strlcpy(tmpfile, SwooleG.task_tmpfile.c_str(), SW_TASK_TMP_PATH_SIZE);
    int tmp_fd = swoole_tmpfile(tmpfile);
    if (tmp_fd < 0) {
        return File(-1);
    } else {
        return File(tmp_fd, std::string(tmpfile, l));
    }
}

bool file_put_contents(const std::string &filename, const char *content, size_t length) {
    if (length <= 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "content is empty");
        return false;
    }
    if (length > SW_MAX_FILE_CONTENT) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "content is too large");
        return false;
    }
    File file(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (!file.ready()) {
        swSysWarn("open(%s) failed", filename.c_str());
        return false;
    }
    return file.write_all(content, length);
}

size_t File::read_all(void *buf, size_t len) {
    ssize_t n = 0;
    size_t count = len, toread, readn = 0;

    while (count > 0) {
        toread = count;
        if (toread > SW_FILE_CHUNK_SIZE) {
            toread = SW_FILE_CHUNK_SIZE;
        }
        n = read(buf, toread);
        if (n > 0) {
            buf = (char *) buf + n;
            count -= n;
            readn += n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            swSysWarn("read() failed");
            break;
        }
    }
    return readn;
}

std::shared_ptr<String> File::read_content() {
    ssize_t n = 0;
    std::shared_ptr<String> data = std::make_shared<String>(SW_BUFFER_SIZE_STD);
    while (1) {
        n = read(data->str + data->length, data->size - data->length);
        if (n <= 0) {
            return data;
        } else {
            if (!data->grow((size_t) n)) {
                return data;
            }
        }
    }
    return data;
}

size_t File::write_all(const void *data, size_t len) {
    ssize_t n = 0;
    size_t count = len, towrite, written = 0;

    while (count > 0) {
        towrite = count;
        if (towrite > SW_FILE_CHUNK_SIZE) {
            towrite = SW_FILE_CHUNK_SIZE;
        }
        n = write(data, towrite);
        if (n > 0) {
            data = (char *) data + n;
            count -= n;
            written += n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            swSysWarn("write(%d, %zu) failed", fd_, towrite);
            break;
        }
    }
    return written;
}

}
