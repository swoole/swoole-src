/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 02aefd39f4852eea3258eea8edb7000fa86af163 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Swoole_Http_Cookie___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setName, 0, 1, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setValue, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, value, IS_STRING, 0, "\'\'")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, encode, _IS_BOOL, 0, "true")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setExpires, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, expires, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setPath, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, path, IS_STRING, 0, "\'/\'")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setDomain, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, domain, IS_STRING, 0, "\'\'")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setSecure, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, secure, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setHttpOnly, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, httpOnly, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setSameSite, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sameSite, IS_STRING, 0, "\'\'")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setPriority, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, priority, IS_STRING, 0, "\'\'")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Swoole_Http_Cookie_setPartitioned, 0, 0, Swoole\\Http\\Cookie, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, partitioned, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Http_Cookie_getCookie, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_Http_Cookie_reset, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()
