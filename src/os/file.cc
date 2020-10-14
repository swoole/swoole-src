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

using swoole::String;
using swoole::File;
using swoole::FileStatus;

ssize_t swoole_file_get_size(FILE *fp) {
    fflush(fp);
    return swoole_file_get_size(fileno(fp));
}

ssize_t swoole_file_get_size(const std::string &filename) {
    File file(filename, File::READ);
    if (!file.ready()) {
        swoole_set_last_error(errno);
        return -1;
    }
    return swoole_file_get_size(file.get_fd());
}

ssize_t swoole_file_get_size(int fd) {
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

std::shared_ptr<String> swoole_file_get_contents(const std::string &filename) {
    long filesize = swoole_file_get_size(filename);
    if (filesize < 0) {
        return nullptr;
    } else if (filesize == 0) {
        swoole_error_log(SW_LOG_TRACE, SW_ERROR_FILE_EMPTY, "file[%s] is empty", filename.c_str());
        return nullptr;
    } else if (filesize > SW_MAX_FILE_CONTENT) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_FILE_TOO_LARGE, "file[%s] is too large", filename.c_str());
        return nullptr;
    }

    File _handler(filename, O_RDONLY);
    int fd = _handler.get_fd();
    if (fd < 0) {
        swSysWarn("open(%s) failed", filename.c_str());
        return nullptr;
    }

    std::shared_ptr<String> content(swString_new(filesize + 1));
    ssize_t read_bytes = 0;

    while (read_bytes < filesize) {
        ssize_t n = pread(fd, content->str + read_bytes, filesize - read_bytes, read_bytes);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                swSysWarn("pread(%d, %ld, %ld) failed", fd, filesize - read_bytes, read_bytes);
                return content;
            }
        }
        read_bytes += n;
    }

    content->length = read_bytes;
    content->str[read_bytes] = '\0';
    return content;
}

bool swoole_file_put_contents(const char *filename, const char *content, size_t length) {
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
        swSysWarn("open(%s) failed", filename);
        return false;
    }

    size_t chunk_size, written = 0;
    while (written < length) {
        chunk_size = length - written;
        if (chunk_size > SW_BUFFER_SIZE_BIG) {
            chunk_size = SW_BUFFER_SIZE_BIG;
        }
        ssize_t n = file.write(content + written, chunk_size);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                swSysWarn("write(%d, %zu) failed", file.get_fd(), chunk_size);
                return -1;
            }
        }
        written += n;
    }
    return true;
}

size_t swoole_sync_readfile(int fd, void *buf, size_t len) {
    ssize_t n = 0;
    size_t count = len, toread, readn = 0;

    while (count > 0) {
        toread = count;
        if (toread > SW_FILE_CHUNK_SIZE) {
            toread = SW_FILE_CHUNK_SIZE;
        }
        n = read(fd, buf, toread);
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

swString *swoole_sync_readfile_eof(int fd) {
    ssize_t n = 0;
    swString *data = new swString(SW_BUFFER_SIZE_STD);
    if (data == nullptr) {
        return data;
    }

    while (1) {
        n = read(fd, data->str + data->length, data->size - data->length);
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

size_t swoole_sync_writefile(int fd, const void *data, size_t len) {
    ssize_t n = 0;
    size_t count = len, towrite, written = 0;

    while (count > 0) {
        towrite = count;
        if (towrite > SW_FILE_CHUNK_SIZE) {
            towrite = SW_FILE_CHUNK_SIZE;
        }
        n = write(fd, data, towrite);
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
            swSysWarn("write(%d, %zu) failed", fd, towrite);
            break;
        }
    }
    return written;
}
