/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: d1e6080cc38fa69333de561b46611af3c98d698d */

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_socket_create_listen, 0, 1, Swoole\\Coroutine\\Socket, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, backlog, IS_LONG, 0, "128")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_socket_accept, 0, 1, Swoole\\Coroutine\\Socket, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_set_nonblock, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_native_socket_set_block arginfo_swoole_native_socket_set_nonblock

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_listen, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, backlog, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_close, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_write, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, length, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_read, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mode, IS_LONG, 0, "PHP_BINARY_READ")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_getsockname, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_INFO(1, address)
	ZEND_ARG_INFO_WITH_DEFAULT_VALUE(1, port, "null")
ZEND_END_ARG_INFO()

#define arginfo_swoole_native_socket_getpeername arginfo_swoole_native_socket_getsockname

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_socket_create, 0, 3, Swoole\\Coroutine\\Socket, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, domain, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, protocol, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_connect, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, address, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, port, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_strerror, 0, 1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, error_code, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_bind, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, address, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, port, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_recv, 0, 4, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_INFO(1, data)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_send, 0, 4, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_recvfrom, 0, 5, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_INFO(1, data)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_INFO(1, address)
	ZEND_ARG_INFO_WITH_DEFAULT_VALUE(1, port, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_sendto, 0, 5, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, address, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, port, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_socket_get_option, 0, 3, MAY_BE_ARRAY|MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, level, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_native_socket_getopt arginfo_swoole_native_socket_get_option

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_set_option, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO(0, level, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

#define arginfo_swoole_native_socket_setopt arginfo_swoole_native_socket_set_option

#if defined(HAVE_SOCKETPAIR)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_create_pair, 0, 4, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, domain, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, protocol, IS_LONG, 0)
	ZEND_ARG_INFO(1, pair)
ZEND_END_ARG_INFO()
#endif

#if defined(HAVE_SHUTDOWN)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_shutdown, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, socket, Swoole\\Coroutine\\Socket, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mode, IS_LONG, 0, "2")
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_last_error, 0, 0, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO_WITH_DEFAULT_VALUE(0, socket, Swoole\\Coroutine\\Socket, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_socket_clear_error, 0, 0, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO_WITH_DEFAULT_VALUE(0, socket, Swoole\\Coroutine\\Socket, 1, "null")
ZEND_END_ARG_INFO()
