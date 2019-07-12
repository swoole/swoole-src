/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2018 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Gustavo Lopes    <cataphract@php.net>                       |
   +----------------------------------------------------------------------+
 */

#include "php_sockets_cxx.h"

#include <limits.h>
#include <Zend/zend_llist.h>
#ifdef ZTS
#include <TSRM/TSRM.h>
#endif

#define MAX_USER_BUFF_SIZE ((size_t)(100*1024*1024))
#define DEFAULT_BUFF_SIZE 8192
#define MAX_ARRAY_KEY_SIZE 128

#define LONG_CHECK_VALID_INT(l) \
	do { \
		if ((l) < INT_MIN && (l) > INT_MAX) { \
			php_error_docref(NULL, E_WARNING, "The value " ZEND_LONG_FMT " does not fit inside " \
					"the boundaries of a native integer", (l)); \
			return; \
		} \
	} while (0)


int php_do_setsockopt_ipv6_rfc3542(Socket *php_sock, int level, int optname, zval *arg4)
{
#ifdef IPV6_PKTINFO
	struct err_s	err = {0};
#endif
	zend_llist		*allocations = NULL;
	void			*opt_ptr;
	socklen_t		optlen;
	int				retval;

	assert(level == IPPROTO_IPV6);

	switch (optname) {
#ifdef IPV6_PKTINFO
	case IPV6_PKTINFO:
		opt_ptr = from_zval_run_conversions(arg4, php_sock, from_zval_write_in6_pktinfo,
				sizeof(struct in6_pktinfo),	"in6_pktinfo", &allocations, &err);
		if (err.has_error) {
			err_msg_dispose(&err);
			return FAILURE;
		}

		optlen = sizeof(struct in6_pktinfo);
		goto dosockopt;
#endif
	}

	/* we also support IPV6_TCLASS, but that can be handled by the default
	 * integer optval handling in the caller */
	return 1;

#ifdef IPV6_PKTINFO
dosockopt:
#endif
	retval = setsockopt(php_sock->get_fd(), level, optname, opt_ptr, optlen);
	if (retval != 0) {
		PHP_SWOOLE_SOCKET_ERROR(php_sock, "unable to set socket option", errno);
	}
	allocations_dispose(&allocations);

	return retval != 0 ? FAILURE : SUCCESS;
}

int php_do_getsockopt_ipv6_rfc3542(Socket *php_sock, int level, int optname, zval *result)
{
    struct err_s err =
    { 0 };
    char *buffer;
    socklen_t size;
    int res;
    to_zval_read_field *reader;

	assert(level == IPPROTO_IPV6);

	switch (optname) {
#ifdef IPV6_PKTINFO
	case IPV6_PKTINFO:
		size = sizeof(struct in6_pktinfo);
		reader = &to_zval_read_in6_pktinfo;
		break;
#endif
	default:
		return 1;
	}

    buffer = (char*) ecalloc(1, size);
	res = getsockopt(php_sock->get_fd(), level, optname, buffer, &size);
	if (res != 0) {
		PHP_SWOOLE_SOCKET_ERROR(php_sock, "unable to get socket option", errno);
	} else {
		zval tmp;
		zval *zv = to_zval_run_conversions(buffer, reader, "in6_pktinfo",
				sw_empty_key_value_list, &err, &tmp);
		if (err.has_error) {
			err_msg_dispose(&err);
			res = -1;
		} else {
			ZVAL_COPY_VALUE(result, zv);
		}
	}
	efree(buffer);

	return res == 0 ? SUCCESS : FAILURE;
}
