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

#ifndef SW_FILE_HOOK_H_
#define SW_FILE_HOOK_H_

#include "swoole_coroutine_c_api.h"

#define access(pathname, mode) swoole_coroutine_access(pathname, mode)
#define open(pathname, flags, mode) swoole_coroutine_open(pathname, flags, mode)
#define read(fd, buf, count) swoole_coroutine_read(fd, buf, count)
#define write(fd, buf, count) swoole_coroutine_write(fd, buf, count)
#define lseek(fd, offset, whence) swoole_coroutine_lseek(fd, offset, whence)
#define fstat(fd, statbuf) swoole_coroutine_fstat(fd, statbuf)
#define readlink(fd, buf, size) swoole_coroutine_readlink(fd, buf, size)
#define unlink(pathname) swoole_coroutine_unlink(pathname)
#define mkdir(pathname, mode) swoole_coroutine_mkdir(pathname, mode)
#define rmdir(pathname) swoole_coroutine_rmdir(pathname)
#define rename(oldpath, newpath) swoole_coroutine_rename(oldpath, newpath)

#define fopen(pathname, mode)  swoole_coroutine_fopen(pathname, mode)
#define fdopen(fd, mode)  swoole_coroutine_fdopen(fd, mode)
#define freopen(pathname, mode, stream)  swoole_coroutine_freopen(pathname, mode, stream)
#define fread(ptr, size, nmemb, stream)  swoole_coroutine_fread(ptr, size, nmemb, stream)
#define fwrite(ptr, size, nmemb, stream)  swoole_coroutine_fwrite(ptr, size, nmemb, stream)
#define fgets(s, size, stream)  swoole_coroutine_fgets(s, size, stream)
#define fputs(s, stream)  swoole_coroutine_fputs(s, stream)
#define feof(stream)  swoole_coroutine_feof(stream)
#define fclose(stream)  swoole_coroutine_fclose(stream)

#define opendir(name) swoole_coroutine_opendir(name)
#define readdir(dir) swoole_coroutine_readdir(dir)
#define closedir(dir) swoole_coroutine_closedir(dir)

#endif
