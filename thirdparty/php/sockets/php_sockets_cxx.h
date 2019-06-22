#pragma once

#include "php_swoole_cxx.h"

#include <php_network.h>
#include <netinet/in.h>

#include "thirdparty/php/sockets/multicast.h"
#include "thirdparty/php/sockets/conversions.h"

using swoole::coroutine::Socket;

#define PHP_SWOOLE_SOCKET_ERROR(socket, msg, errn) \
        do { \
            int _err = (errn); /* save value to avoid repeated calls to WSAGetLastError() on Windows */ \
            (socket)->errCode = _err; \
            if (_err != EAGAIN && _err != EWOULDBLOCK && _err != EINPROGRESS) { \
                php_error_docref(NULL, E_WARNING, "%s [%d]: %s", msg, _err, strerror(_err)); \
            } \
        } while (0)

int php_do_setsockopt_ipv6_rfc3542(Socket *php_sock, int level, int optname, zval *arg4);
int php_do_getsockopt_ipv6_rfc3542(Socket *php_sock, int level, int optname, zval *result);

int php_string_to_if_index(const char *val, unsigned *out);

/*
 * Convert an IPv6 literal or a hostname info a sockaddr_in6.
 * The IPv6 literal can be a IPv4 mapped address (like ::ffff:127.0.0.1).
 * If the hostname yields no IPv6 addresses, a mapped IPv4 address may be returned (AI_V4MAPPED)
 */
int php_set_inet6_addr(struct sockaddr_in6 *sin6, char *string, Socket *php_sock);

/*
 * Convert an IPv4 literal or a hostname into a sockaddr_in.
 */
int php_set_inet_addr(struct sockaddr_in *sin, char *string, Socket *php_sock);

/*
 * Calls either php_set_inet6_addr() or php_set_inet_addr(), depending on the type of the socket.
 */
int php_set_inet46_addr(php_sockaddr_storage *ss, socklen_t *ss_len, char *string, Socket *php_sock);
