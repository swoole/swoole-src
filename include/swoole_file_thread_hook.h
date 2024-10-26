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

#ifndef SWOOLE_SRC_SWOOLE_FILE_THREAD_HOOK_H
#define SWOOLE_SRC_SWOOLE_FILE_THREAD_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#ifdef __APPLE__
extern int fdatasync(int);
#endif

// file thread engine
int swoole_coroutine_access(const char *pathname, int mode);
int swoole_coroutine_open(const char *pathname, int flags, mode_t mode);
ssize_t swoole_coroutine_read(int fd, void *buf, size_t count);
ssize_t swoole_coroutine_write(int fd, const void *buf, size_t count);
off_t swoole_coroutine_lseek(int fd, off_t offset, int whence);
int swoole_coroutine_fstat(int fd, struct stat *statbuf);
int swoole_coroutine_stat(const char *path, struct stat *statbuf);
int swoole_coroutine_lstat(const char *path, struct stat *statbuf);
int swoole_coroutine_readlink(const char *pathname, char *buf, size_t len);
int swoole_coroutine_unlink(const char *pathname);
int swoole_coroutine_mkdir(const char *pathname, mode_t mode);
int swoole_coroutine_rmdir(const char *pathname);
int swoole_coroutine_rename(const char *oldpath, const char *newpath);
int swoole_coroutine_flock(int fd, int operation);
int swoole_coroutine_flock_ex(const char *filename, int fd, int operation);
int swoole_coroutine_statvfs(const char *path, struct statvfs *buf);
int swoole_coroutine_close_file(int fd);
int swoole_coroutine_fsync(int fd);
int swoole_coroutine_fdatasync(int fd);

// stdio
FILE *swoole_coroutine_fopen(const char *pathname, const char *mode);
FILE *swoole_coroutine_fdopen(int fd, const char *mode);
FILE *swoole_coroutine_freopen(const char *pathname, const char *mode, FILE *stream);
size_t swoole_coroutine_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t swoole_coroutine_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
char *swoole_coroutine_fgets(char *s, int size, FILE *stream);
int swoole_coroutine_fputs(const char *s, FILE *stream);
int swoole_coroutine_feof(FILE *stream);
int swoole_coroutine_fclose(FILE *stream);

// dir
DIR *swoole_coroutine_opendir(const char *name);
struct dirent *swoole_coroutine_readdir(DIR *dirp);
int swoole_coroutine_closedir(DIR *dirp);

#ifdef __cplusplus
} /* end extern "C" */
#endif
#endif  // SWOOLE_SRC_SWOOLE_FILE_THREAD_HOOK_H
