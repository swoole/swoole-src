ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_dns_lookup_coro, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_defer, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_socketpair, 0, 0, 3)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, protocol)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_test_kernel_coroutine, 0, 0, 0)
    ZEND_ARG_INFO(0, count)
    ZEND_ARG_INFO(0, sleep_time)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_select, 0, 0, 3)
    ZEND_ARG_INFO(1, read_array)
    ZEND_ARG_INFO(1, write_array)
    ZEND_ARG_INFO(1, error_array)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_substr_unserialize, 0, 0, 2)
    ZEND_ARG_INFO(0, str)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

#ifdef SW_USE_JSON
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_substr_json_decode, 0, 0, 2)
    ZEND_ARG_INFO(0, json)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, associative)
    ZEND_ARG_INFO(0, depth)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_set_process_name, 0, 0, 1)
    ZEND_ARG_INFO(0, process_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_strerror, 0, 0, 1)
    ZEND_ARG_INFO(0, errno)
    ZEND_ARG_INFO(0, error_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_error_log, 0, 0, 2)
    ZEND_ARG_INFO(0, level)
    ZEND_ARG_INFO(0, msg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_error_log_ex, 0, 0, 3)
    ZEND_ARG_INFO(0, level)
    ZEND_ARG_INFO(0, error)
    ZEND_ARG_INFO(0, msg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_ignore_error, 0, 0, 1)
    ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_hashcode, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

/* add/set */
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mime_type_write, 0, 0, 2)
    ZEND_ARG_INFO(0, suffix)
    ZEND_ARG_INFO(0, mime_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mime_type_delete, 0, 0, 1)
    ZEND_ARG_INFO(0, suffix)
ZEND_END_ARG_INFO()

/* get/exists */
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mime_type_read, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

#define arginfo_swoole_version                           arginfo_swoole_void
#define arginfo_swoole_cpu_num                           arginfo_swoole_void
#define arginfo_swoole_last_error                        arginfo_swoole_void
#define arginfo_swoole_get_local_ip                      arginfo_swoole_void
#define arginfo_swoole_get_local_mac                     arginfo_swoole_void
#define arginfo_swoole_errno                             arginfo_swoole_void
#define arginfo_swoole_clear_error                       arginfo_swoole_void
#define arginfo_swoole_mime_type_add                     arginfo_swoole_mime_type_write
#define arginfo_swoole_mime_type_set                     arginfo_swoole_mime_type_write
#define arginfo_swoole_mime_type_get                     arginfo_swoole_mime_type_read
#define arginfo_swoole_mime_type_exists                  arginfo_swoole_mime_type_read
#define arginfo_swoole_mime_type_list                    arginfo_swoole_void
#define arginfo_swoole_clear_dns_cache                   arginfo_swoole_void
#define arginfo_swoole_internal_call_user_shutdown_begin arginfo_swoole_void
