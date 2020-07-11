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

#ifndef SW_FILE_HOOK_H_
#define SW_FILE_HOOK_H_

#include "coroutine_c_api.h"

#define access(pathname, mode) swoole_coroutine_access(pathname, mode)
#define open(pathname, flags, mode) swoole_coroutine_open(pathname, flags, mode)
#define read(fd, buf, count) swoole_coroutine_read(fd, buf, count)
#define write(fd, buf, count) swoole_coroutine_write(fd, buf, count)
#define lseek(fd, offset, whence) swoole_coroutine_lseek(fd, offset, whence)
#define fstat(fd, statbuf) swoole_coroutine_fstat(fd, statbuf)
#define unlink(pathname) swoole_coroutine_unlink(pathname)
#define mkdir(pathname, mode) swoole_coroutine_mkdir(pathname, mode)
#define rmdir(pathname) swoole_coroutine_rmdir(pathname)
#define rename(oldpath, newpath) swoole_coroutine_rename(oldpath, newpath)

#if 0
DIR *swoole_coroutine_opendir(const char *name);
struct dirent *swoole_coroutine_readdir(DIR *dirp);
#define opendir(name) swoole_coroutine_opendir(name)
#define readdir(dir) swoole_coroutine_readdir(dir)
#endif

#endif
