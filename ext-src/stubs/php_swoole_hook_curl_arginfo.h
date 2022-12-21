/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: cd08c0997033b1d14946f2db45d6a23f33c5d3ec */

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_hook_curl_init, 0, 0, Swoole\\Curl\\Handler, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, url, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_setopt, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
	ZEND_ARG_TYPE_INFO(0, opt, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_setopt_array, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
	ZEND_ARG_TYPE_INFO(0, array, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_hook_curl_exec, 0, 1, MAY_BE_STRING|MAY_BE_BOOL)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_getinfo, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, opt, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_errno, 0, 1, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_error, 0, 1, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_reset, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_hook_curl_close arginfo_swoole_hook_curl_reset

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_hook_curl_multi_getcontent, 0, 1, IS_STRING, 1)
	ZEND_ARG_OBJ_INFO(0, obj, Swoole\\Curl\\Handler, 0)
ZEND_END_ARG_INFO()
