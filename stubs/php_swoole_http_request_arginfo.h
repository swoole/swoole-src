/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: b0c17f03a4ba82e0d284add4ea52e8e913a97a17 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Http_Request___destruct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Http_Request_getData, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_Http_Request_create, 0, 0, Swoole\\Http\\Request, MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Http_Request_parse, 0, 1, MAY_BE_LONG|MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Http_Request_isCompleted, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_class_Swoole_Http_Request_getMethod, 0, 0, MAY_BE_STRING|MAY_BE_BOOL)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Http_Request_getContent arginfo_class_Swoole_Http_Request_getMethod
