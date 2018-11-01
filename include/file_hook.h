#include "coroutine_c_api.h"

#define access(pathname, mode)             swoole_coroutine_access(pathname, mode)
#define open(pathname, flags, mode)        swoole_coroutine_open(pathname, flags, mode)
#define read(fd, buf, count)               swoole_coroutine_read(fd, buf, count)
#define write(fd, buf, count)              swoole_coroutine_write(fd, buf, count)
#define lseek(fd, offset, whence)          swoole_coroutine_lseek(fd, offset, whence)
#define fstat(fd, statbuf)                 swoole_coroutine_fstat(fd, statbuf)
#define unlink(pathname)                   swoole_coroutine_unlink(pathname)
#define mkdir(pathname, mode)              swoole_coroutine_mkdir(pathname, mode)
#define rmdir(pathname)                    swoole_coroutine_rmdir(pathname)
#define rename(oldpath, newpath)           swoole_coroutine_rename(oldpath, newpath)

#if 0
DIR *swoole_coroutine_opendir(const char *name);
struct dirent *swoole_coroutine_readdir(DIR *dirp);
#define opendir(name)                      swoole_coroutine_opendir(name)
#define readdir(dir)                       swoole_coroutine_readdir(dir)
#endif
