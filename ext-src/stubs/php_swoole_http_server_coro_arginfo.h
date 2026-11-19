/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: c7488cc3a1e14a34a6583c97d37cba1c87ef2201 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server___construct, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, port, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, ssl, _IS_BOOL, 0, "false")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reuse_port, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server___destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server_set, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server_handle, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, pattern, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server_start, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server_shutdown, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Coroutine_Http_Server_onAccept, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, conn, Swoole\\Coroutine\\Socket, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Http_Server_onFlush arginfo_class_Swoole_Coroutine_Http_Server_onAccept

