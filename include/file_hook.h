int swoole_coroutine_access(const char *pathname, int mode);
int swoole_coroutine_open(const char *pathname, int flags, mode_t mode);
ssize_t swoole_coroutine_read(int fd, void *buf, size_t count);
ssize_t swoole_coroutine_write(int fd, const void *buf, size_t count);
off_t swoole_coroutine_lseek(int fd, off_t offset, int whence);
int swoole_coroutine_fstat(int fd, struct stat *statbuf);
int swoole_coroutine_unlink(const char *pathname);
int swoole_coroutine_mkdir(const char *pathname, mode_t mode);
int swoole_coroutine_rmdir(const char *pathname);
int swoole_coroutine_rename(const char *oldpath, const char *newpath);


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
