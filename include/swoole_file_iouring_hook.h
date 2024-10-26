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

#ifndef SWOOLE_SRC_SWOOLE_FILE_IOURING_HOOK_H
#define SWOOLE_SRC_SWOOLE_FILE_IOURING_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stat.h>
#include <sys/statvfs.h>

/**
 * file io_uring engine
 */
#ifdef SW_USE_IOURING
int swoole_coroutine_iouring_open(const char *pathname, int flags, mode_t mode);
int swoole_coroutine_iouring_close_file(int fd);
ssize_t swoole_coroutine_iouring_read(int sockfd, void *buf, size_t count);
ssize_t swoole_coroutine_iouring_write(int sockfd, const void *buf, size_t count);
int swoole_coroutine_iouring_rename(const char *oldpath, const char *newpath);
int swoole_coroutine_iouring_mkdir(const char *pathname, mode_t mode);
int swoole_coroutine_iouring_unlink(const char *pathname);
int swoole_coroutine_iouring_fstat(int fd, struct stat *statbuf);
int swoole_coroutine_iouring_stat(const char *path, struct stat *statbuf);
int swoole_coroutine_iouring_lstat(const char *path, struct stat *statbuf);
int swoole_coroutine_iouring_rmdir(const char *pathname);
int swoole_coroutine_iouring_fsync(int fd);
int swoole_coroutine_iouring_fdatasync(int fd);
void swoole_statx_to_stat(const struct statx *statxbuf, struct stat *statbuf);
#endif

#ifdef __cplusplus
} /* end extern "C" */
#endif
#endif  // SWOOLE_SRC_SWOOLE_FILE_IOURING_HOOK_H
