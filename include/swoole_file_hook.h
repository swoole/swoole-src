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

#include "swoole_coroutine_api.h"

#define open(pathname, flags, mode) swoole_coroutine_open(pathname, flags, mode)
#define close(fd) swoole_coroutine_close(fd)
#define read(fd, buf, count) swoole_coroutine_read(fd, buf, count)
#define write(fd, buf, count) swoole_coroutine_write(fd, buf, count)
#define lseek(fd, offset, whence) swoole_coroutine_lseek(fd, offset, whence)
#ifdef _WIN32
// On Windows, swoole_win32.h already defines lstat as stat, realpath as _fullpath, etc.
// readlink is not available on Windows; skip macro
// PHP's php.h already defines mkdir/rmdir on Windows; guard to avoid redefinition
#ifndef mkdir
#define mkdir(pathname, mode) swoole_coroutine_mkdir(pathname, mode)
#endif
#ifndef rmdir
#define rmdir(pathname) swoole_coroutine_rmdir(pathname)
#endif
#else
#define readlink(fd, buf, size) swoole_coroutine_readlink(fd, buf, size)
#define mkdir(pathname, mode) swoole_coroutine_mkdir(pathname, mode)
#define rmdir(pathname) swoole_coroutine_rmdir(pathname)
#endif
#define rename(oldpath, newpath) swoole_coroutine_rename(oldpath, newpath)
// fsync and ftruncate may already be defined by PHP's php_network.h on Windows
#ifndef fsync
#define fsync(fd) swoole_coroutine_fsync(fd)
#endif
#define fdatasync(fd) swoole_coroutine_fdatasync(fd)
#ifndef ftruncate
#define ftruncate(fd, length) swoole_coroutine_ftruncate(fd, length)
#endif

// access may already be defined by swoole_win32.h as sw_access
// Override it for coroutine hooking
#ifdef access
#undef access
#endif
#define access(pathname, mode) swoole_coroutine_access(pathname, mode)
#define fopen(pathname, mode) swoole_coroutine_fopen(pathname, mode)
#define fdopen(fd, mode) swoole_coroutine_fdopen(fd, mode)
#define freopen(pathname, mode, stream) swoole_coroutine_freopen(pathname, mode, stream)
#define fread(ptr, size, nmemb, stream) swoole_coroutine_fread(ptr, size, nmemb, stream)
#define fwrite(ptr, size, nmemb, stream) swoole_coroutine_fwrite(ptr, size, nmemb, stream)
#define fgets(s, size, stream) swoole_coroutine_fgets(s, size, stream)
#define fputs(s, stream) swoole_coroutine_fputs(s, stream)
#define feof(stream) swoole_coroutine_feof(stream)
#define fflush(stream) swoole_coroutine_fflush(stream)
#define fclose(stream) swoole_coroutine_fclose(stream)

#define opendir(name) swoole_coroutine_opendir(name)
#define readdir(dir) swoole_coroutine_readdir(dir)
#define closedir(dir) swoole_coroutine_closedir(dir)

#endif
