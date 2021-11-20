/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: ea1c9962d0c6f69619db83a71bdbea7dbaa8ec89 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Client___construct, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, type, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, async, IS_LONG, 0, "SWOOLE_SOCK_SYNC")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, id, IS_STRING, 0, "\'\'")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Client___destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_set, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_connect, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "0.5")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sock_flag, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Client_recv, 0, 0, MAY_BE_STRING|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, size, IS_LONG, 0, "65536")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flag, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Client_send, 0, 1, MAY_BE_BOOL|MAY_BE_LONG)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flag, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_sendfile, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, offset, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, length, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_sendto, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, ip, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_enableSSL, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Client_getPeerCert, 0, 0, MAY_BE_STRING|MAY_BE_BOOL)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Client_verifyPeerCert arginfo_class_Swoole_Client_enableSSL

#define arginfo_class_Swoole_Client_isConnected arginfo_class_Swoole_Client_enableSSL

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Client_getsockname, 0, 0, MAY_BE_ARRAY|MAY_BE_BOOL)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Client_getpeername arginfo_class_Swoole_Client_getsockname

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_close, 0, 0, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, force, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Client_shutdown, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, how, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Client_getSocket arginfo_class_Swoole_Client_enableSSL
