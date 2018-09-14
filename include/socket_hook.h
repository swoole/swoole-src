#ifndef SW_SOCKET_HOOK_H_
#define SW_SOCKET_HOOK_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>

#ifdef __cplusplus
extern "C" {
#endif

int swoole_coroutine_socket(int domain, int type, int protocol);
ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t swoole_coroutine_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t swoole_coroutine_recvmsg(int sockfd, struct msghdr *msg, int flags);
int swoole_coroutine_close(int fd);
int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int swoole_coroutine_poll(struct pollfd *fds, nfds_t nfds, int timeout);

#define socket(domain, type, protocol)  swoole_coroutine_socket(domain, type, protocol)
#define send(sockfd, buf, len, flags)   swoole_coroutine_send(sockfd, buf, len, flags)
#define recv(sockfd, buf, len, flags)   swoole_coroutine_recv(sockfd, buf, len, flags)
#define close(fd)                       swoole_coroutine_close(fd)
#define connect(sockfd, addr, addrlen)  swoole_coroutine_connect(sockfd, addr, addrlen)
#define poll(fds, nfds, timeout)        swoole_coroutine_poll(fds, nfds, timeout)
#define sendmsg(sockfd, msg, flags)     swoole_coroutine_sendmsg(sockfd, msg, flags)
#define recvmsg(sockfd, msg, flags)     swoole_coroutine_recvmsg(sockfd, msg, flags)

#ifdef __cplusplus
}
#endif

#endif
