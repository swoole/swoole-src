/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 6f7042ee0dbb6c3e3c24140519c71baec937f773 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Server_Port___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Server_Port___destruct arginfo_class_Swoole_Server_Port___construct

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Server_Port_set, 0, 1, MAY_BE_NULL|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, settings, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Server_Port_on, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, event_name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Server_Port_getCallback, 0, 1, Closure, 1)
	ZEND_ARG_TYPE_INFO(0, event_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Server_Port_getSocket, 0, 0, MAY_BE_FALSE|MAY_BE_OBJECT)
ZEND_END_ARG_INFO()
