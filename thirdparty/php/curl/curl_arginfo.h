/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: f1d616c644ad366405816cde0384f6f391773ebf */

#ifdef SW_USE_CURL

#include "zend_API.h"

#include <curl/curl.h>
#include <curl/multi.h>

SW_EXTERN_C_BEGIN
PHP_FUNCTION(swoole_native_curl_close);
PHP_FUNCTION(swoole_native_curl_copy_handle);
PHP_FUNCTION(swoole_native_curl_errno);
PHP_FUNCTION(swoole_native_curl_error);
PHP_FUNCTION(swoole_native_curl_exec);
PHP_FUNCTION(swoole_native_curl_getinfo);
PHP_FUNCTION(swoole_native_curl_init);
PHP_FUNCTION(swoole_native_curl_setopt);
PHP_FUNCTION(swoole_native_curl_setopt_array);

#if LIBCURL_VERSION_NUM >= 0x070c01 /* 7.12.1 */
PHP_FUNCTION(swoole_native_curl_reset);
#endif

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
PHP_FUNCTION(swoole_native_curl_escape);
PHP_FUNCTION(swoole_native_curl_unescape);
#endif

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
PHP_FUNCTION(swoole_native_curl_pause);
#endif
SW_EXTERN_C_END

#if PHP_VERSION_ID >= 80000

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_close, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_copy_handle, 0, 1, CurlHandle, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_errno, 0, 1, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_error, 0, 1, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_escape, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
	ZEND_ARG_TYPE_INFO(0, string, IS_STRING, 0)
ZEND_END_ARG_INFO()
#endif

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
#define arginfo_swoole_native_curl_unescape arginfo_swoole_native_curl_escape
#endif

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_exec, 0, 1, MAY_BE_STRING|MAY_BE_BOOL)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_swoole_native_curl_file_create, 0, 1, CURLFile, 0)
	ZEND_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mime_type, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, posted_filename, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_getinfo, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, option, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_init, 0, 0, Swoole\\Coroutine\\Curl\\Handle, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, url, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_pause, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()
#endif

#define arginfo_swoole_native_curl_reset arginfo_swoole_native_curl_close

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt_array, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
	ZEND_ARG_TYPE_INFO(0, options, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, Swoole\\Coroutine\\Curl\\Handle, 0)
	ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_native_curl_functions[] = {
    ZEND_FENTRY(curl_close, PHP_FN(swoole_native_curl_close), arginfo_swoole_native_curl_close, 0)
    ZEND_FENTRY(curl_copy_handle, PHP_FN(swoole_native_curl_copy_handle), arginfo_swoole_native_curl_copy_handle, 0)
    ZEND_FENTRY(curl_errno, PHP_FN(swoole_native_curl_errno), arginfo_swoole_native_curl_errno, 0)
    ZEND_FENTRY(curl_error, PHP_FN(swoole_native_curl_error), arginfo_swoole_native_curl_error, 0)
    ZEND_FENTRY(curl_exec, PHP_FN(swoole_native_curl_exec), arginfo_swoole_native_curl_exec, 0)
    ZEND_FENTRY(curl_getinfo, PHP_FN(swoole_native_curl_getinfo), arginfo_swoole_native_curl_getinfo, 0)
    ZEND_FENTRY(curl_init, PHP_FN(swoole_native_curl_init), arginfo_swoole_native_curl_init, 0)
    ZEND_FENTRY(curl_setopt, PHP_FN(swoole_native_curl_setopt), arginfo_swoole_native_curl_setopt, 0)
    ZEND_FENTRY(curl_setopt_array, PHP_FN(swoole_native_curl_setopt_array), arginfo_swoole_native_curl_setopt_array, 0)
    #if LIBCURL_VERSION_NUM >= 0x070c01 /* 7.12.1 */
    ZEND_FENTRY(curl_reset, PHP_FN(swoole_native_curl_reset), arginfo_swoole_native_curl_reset, 0)
    #endif
    #if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
    ZEND_FENTRY(curl_escape, PHP_FN(swoole_native_curl_escape), arginfo_swoole_native_curl_escape, 0)
    ZEND_FENTRY(curl_unescape, PHP_FN(swoole_native_curl_unescape), arginfo_swoole_native_curl_unescape, 0)
    #endif
    #if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
    ZEND_FENTRY(curl_pause, PHP_FN(swoole_native_curl_pause), arginfo_swoole_native_curl_pause, 0)
    #endif
    PHP_FE_END
};
#endif
#endif
