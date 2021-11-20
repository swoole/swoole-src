/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: fbd69a6ebbe55770ce7fc45397cac0f7dde673a6 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Server_Port___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Server_Port___destruct arginfo_class_Swoole_Server_Port___construct

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Server_Port_set, 0, 1, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Server_Port_on, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, event_name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_Server_Port_getCallback, 0, 1, Closure, MAY_BE_NULL)
	ZEND_ARG_TYPE_INFO(0, event_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Server_Port_getSocket, 0, 0, MAY_BE_BOOL|MAY_BE_OBJECT)
ZEND_END_ARG_INFO()
