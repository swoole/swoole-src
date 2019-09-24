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

#ifndef SW_COROUTINE_API_H_
#define SW_COROUTINE_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <poll.h>

/**
 * base
 */
uint8_t swoole_coroutine_is_in();
long swoole_coroutine_get_current_id();
void swoole_coroutine_sleep(int sec);
void swoole_coroutine_usleep(int usec);
/**
 * file
 */
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
int swoole_coroutine_flock(int fd, int operation);
int swoole_coroutine_flock_ex(char *filename, int fd, int operation);
int swoole_coroutine_statvfs(const char *path, struct statvfs *buf);

/**
 * socket
 */
int swoole_coroutine_socket(int domain, int type, int protocol);
ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags);
int swoole_coroutine_close(int fd);
int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int swoole_coroutine_socket_set_timeout(int fd, int which, double timeout);
int swoole_coroutine_socket_wait_event(int fd, int event, double timeout);

/**
 * wait
 */
void swoole_coroutine_signal_init();
size_t swoole_coroutine_wait_count();
pid_t swoole_coroutine_waitpid(pid_t __pid, int *__stat_loc, int __options);
pid_t swoole_coroutine_wait(int *__stat_loc);

#ifdef __cplusplus
}  /* end extern "C" */
#endif
#endif
