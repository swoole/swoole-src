#ifndef SW_SOCKET_HOOK_H_
#define SW_SOCKET_HOOK_H_

#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int swoole_coroutine_socket(int domain, int type, int protocol);
ssize_t swoole_coroutine_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t swoole_coroutine_recv(int sockfd, void *buf, size_t len, int flags);
int swoole_coroutine_close(int fd);
int swoole_coroutine_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#define socket(domain, type, protocol)  swoole_coroutine_socket(domain, type, protocol)
#define send(sockfd, buf, len, flags)   swoole_coroutine_send(sockfd, buf, len, flags)
#define recv(sockfd, buf, len, flags)   swoole_coroutine_recv(sockfd, buf, len, flags)
#define close(fd)                       swoole_coroutine_close(fd)
#define connect(sockfd, addr, addrlen)  swoole_coroutine_connect(sockfd, addr, addrlen)

#ifdef __cplusplus
}
#endif

#endif
