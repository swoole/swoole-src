/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: f1d616c644ad366405816cde0384f6f391773ebf */

#include "curl_interface.h"

#ifdef SW_USE_CURL
#if PHP_VERSION_ID >= 80000

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_close, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_copy_handle, 0, 1, CurlHandle, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_errno, 0, 1, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_error, 0, 1, IS_STRING, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_escape, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, string, IS_STRING, 0)
ZEND_END_ARG_INFO()
#endif

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
#define arginfo_swoole_native_curl_unescape arginfo_swoole_native_curl_escape
#endif

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_exec, 0, 1, MAY_BE_STRING|MAY_BE_BOOL)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_swoole_native_curl_file_create, 0, 1, CURLFile, 0)
	ZEND_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, mime_type, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, posted_filename, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_getinfo, 0, 1, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, option, IS_LONG, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_swoole_native_curl_init, 0, 0, CurlHandle, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, url, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_add_handle, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_close, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_errno, 0, 1, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_exec, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
	ZEND_ARG_INFO(1, still_running)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_getcontent, 0, 1, IS_STRING, 1)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_swoole_native_curl_multi_info_read, 0, 1, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
	ZEND_ARG_INFO_WITH_DEFAULT_VALUE(1, queued_messages, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_swoole_native_curl_multi_init, 0, 0, CurlMultiHandle, 0)
ZEND_END_ARG_INFO()

#define arginfo_swoole_native_curl_multi_remove_handle arginfo_swoole_native_curl_multi_add_handle

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_select, 0, 1, IS_LONG, 0)
    ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 0, "1.0")
ZEND_END_ARG_INFO()

#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_multi_setopt, 0, 3, _IS_BOOL, 0)
    ZEND_ARG_OBJ_INFO(0, multi_handle, CurlMultiHandle, 0)
    ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()
#endif

#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_pause, 0, 2, IS_LONG, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()
#endif

#define arginfo_swoole_native_curl_reset arginfo_swoole_native_curl_close

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt_array, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, options, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_native_curl_setopt, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, handle, CurlHandle, 0)
	ZEND_ARG_TYPE_INFO(0, option, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_native_curl_functions[] = {
    PHP_FE(swoole_native_curl_close, arginfo_swoole_native_curl_close)
    PHP_FE(swoole_native_curl_copy_handle, arginfo_swoole_native_curl_copy_handle)
    PHP_FE(swoole_native_curl_errno, arginfo_swoole_native_curl_errno)
    PHP_FE(swoole_native_curl_error, arginfo_swoole_native_curl_error)
    PHP_FE(swoole_native_curl_exec, arginfo_swoole_native_curl_exec)
    PHP_FE(swoole_native_curl_getinfo, arginfo_swoole_native_curl_getinfo)
    PHP_FE(swoole_native_curl_init, arginfo_swoole_native_curl_init)
    PHP_FE(swoole_native_curl_setopt, arginfo_swoole_native_curl_setopt)
    PHP_FE(swoole_native_curl_setopt_array, arginfo_swoole_native_curl_setopt_array)
#if LIBCURL_VERSION_NUM >= 0x070c01 /* 7.12.1 */
    PHP_FE(swoole_native_curl_reset, arginfo_swoole_native_curl_reset)
#endif
#if LIBCURL_VERSION_NUM >= 0x070f04 /* 7.15.4 */
    PHP_FE(swoole_native_curl_escape, arginfo_swoole_native_curl_escape)
    PHP_FE(swoole_native_curl_unescape, arginfo_swoole_native_curl_unescape)
#endif
#if LIBCURL_VERSION_NUM >= 0x071200 /* 7.18.0 */
    PHP_FE(swoole_native_curl_pause, arginfo_swoole_native_curl_pause)
#endif

    PHP_FE(swoole_native_curl_multi_add_handle, arginfo_swoole_native_curl_multi_add_handle)
    PHP_FE(swoole_native_curl_multi_close, arginfo_swoole_native_curl_multi_close)
    PHP_FE(swoole_native_curl_multi_errno, arginfo_swoole_native_curl_multi_errno)
    PHP_FE(swoole_native_curl_multi_exec, arginfo_swoole_native_curl_multi_exec)
    PHP_FE(swoole_native_curl_multi_select, arginfo_swoole_native_curl_multi_select)
    PHP_FE(swoole_native_curl_multi_setopt, arginfo_swoole_native_curl_multi_setopt)
    PHP_FE(swoole_native_curl_multi_getcontent, arginfo_swoole_native_curl_multi_getcontent)
    PHP_FE(swoole_native_curl_multi_info_read, arginfo_swoole_native_curl_multi_info_read)
    PHP_FE(swoole_native_curl_multi_init, arginfo_swoole_native_curl_multi_init)
    PHP_FE(swoole_native_curl_multi_remove_handle, arginfo_swoole_native_curl_multi_remove_handle)

    PHP_FE_END
};
#endif
#endif
