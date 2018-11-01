#ifndef SW_SOCKET_HOOK_H_
#define SW_SOCKET_HOOK_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "coroutine_c_api.h"

#define socket(domain, type, protocol)  swoole_coroutine_socket(domain, type, protocol)
#define send(sockfd, buf, len, flags)   swoole_coroutine_send(sockfd, buf, len, flags)
#define read(sockfd, buf, len)          swoole_coroutine_read(sockfd, buf, len)
#define write(sockfd, buf, len)         swoole_coroutine_write(sockfd, buf, len)
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
