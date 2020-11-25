/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: f1d616c644ad366405816cde0384f6f391773ebf */

#include "zend_API.h"

#include <curl/curl.h>
#include <curl/multi.h>

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_close, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_copy_handle, 0, 1, CurlHandle, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_errno, 0, 1, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_error, 0, 1, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_escape, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, string, IS_STRING, 0)
ZEND_END_ARG_INFO()
#endif

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
#define arginfo_swoole_native_curl_unescape arginfo_swoole_native_curl_escape
#endif

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_exec, 0, 1, MAY_BE_STRING|MAY_BE_BOOL)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_swoole_native_curl_file_create, 0, 1, CURLFile, 0)
	ZEND_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mime_type, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, posted_filename, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_getinfo, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, option, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_init, 0, 0, Swoole\\Coroutine\\CurlHandle, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, url, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_pause, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()
#endif

#define arginfo_swoole_native_curl_reset arginfo_swoole_native_curl_close

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt_array, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, options, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()
