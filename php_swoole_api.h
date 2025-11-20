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

#ifndef PHP_SWOOLE_API_H
#define PHP_SWOOLE_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "php.h"
#include "php_network.h"

int php_async_socket_connect_to_host(const char *host, unsigned short port,
		int socktype, int asynchronous, struct timeval *timeout, zend_string **error_string,
		int *error_code, const char *bindto, unsigned short bindport, long sockopts);

int php_async_pollfd_for_ms(php_socket_t fd, int events, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* PHP_SWOOLE_API_H */
