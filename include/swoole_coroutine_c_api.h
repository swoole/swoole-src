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

#ifndef SW_COROUTINE_API_H_
#define SW_COROUTINE_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <netdb.h>
#include <poll.h>

// base
uint8_t swoole_coroutine_is_in(void);
long swoole_coroutine_get_current_id(void);
void swoole_coroutine_sleep(int sec);
void swoole_coroutine_usleep(int usec);

// socket
int swoole_coroutine_socket(int domain, int type, int protocol);
int swoole_coroutine_socket_create(int fd);
int swoole_coroutine_socket_unwrap(int fd);
uint8_t swoole_coroutine_socket_exists(int fd);
ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags);
int swoole_coroutine_close(int fd);
int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int swoole_coroutine_poll_fake(struct pollfd *fds, nfds_t nfds, int timeout);
int swoole_coroutine_socket_set_timeout(int fd, int which, double timeout);
int swoole_coroutine_socket_set_connect_timeout(int fd, double timeout);
int swoole_coroutine_socket_wait_event(int fd, int event, double timeout);
int swoole_coroutine_getaddrinfo(const char *name,
                                 const char *service,
                                 const struct addrinfo *req,
                                 struct addrinfo **pai);
struct hostent *swoole_coroutine_gethostbyname(const char *name);

// wait
size_t swoole_coroutine_wait_count(void);
pid_t swoole_coroutine_waitpid(pid_t __pid, int *__stat_loc, int __options);
pid_t swoole_coroutine_wait(int *__stat_loc);

#ifdef __cplusplus
} /* end extern "C" */
#endif
#endif
