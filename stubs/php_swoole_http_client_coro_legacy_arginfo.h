ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setMethod, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setHeaders, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setBasicAuth, 0, 0, 2)
    ZEND_ARG_INFO(0, username)
    ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setCookies, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cookies, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setData, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_addFile, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_addData, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_execute, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_get, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_post, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_download, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, file)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_upgrade, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Coroutine_Http_Client___construct   arginfo_swoole_http_client_coro_coro_construct
#define arginfo_class_Swoole_Coroutine_Http_Client___destruct    arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_set           arginfo_swoole_http_client_coro_set
#define arginfo_class_Swoole_Coroutine_Http_Client_getDefer      arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_setDefer      arginfo_swoole_http_client_coro_setDefer
#define arginfo_class_Swoole_Coroutine_Http_Client_setMethod     arginfo_swoole_http_client_coro_setMethod
#define arginfo_class_Swoole_Coroutine_Http_Client_setHeaders    arginfo_swoole_http_client_coro_setHeaders
#define arginfo_class_Swoole_Coroutine_Http_Client_setBasicAuth  arginfo_swoole_http_client_coro_setBasicAuth
#define arginfo_class_Swoole_Coroutine_Http_Client_setCookies    arginfo_swoole_http_client_coro_setCookies
#define arginfo_class_Swoole_Coroutine_Http_Client_setData       arginfo_swoole_http_client_coro_setData
#define arginfo_class_Swoole_Coroutine_Http_Client_addFile       arginfo_swoole_http_client_coro_addFile
#define arginfo_class_Swoole_Coroutine_Http_Client_addData       arginfo_swoole_http_client_coro_addData
#define arginfo_class_Swoole_Coroutine_Http_Client_execute       arginfo_swoole_http_client_coro_execute
#define arginfo_class_Swoole_Coroutine_Http_Client_getpeername   arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_getsockname   arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_get           arginfo_swoole_http_client_coro_get
#define arginfo_class_Swoole_Coroutine_Http_Client_post          arginfo_swoole_http_client_coro_post
#define arginfo_class_Swoole_Coroutine_Http_Client_download      arginfo_swoole_http_client_coro_download
#define arginfo_class_Swoole_Coroutine_Http_Client_getBody       arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_getHeaders    arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_getCookies    arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_getStatusCode arginfo_swoole_void
#define arginfo_class_Swoole_Coroutine_Http_Client_getHeaderOut  arginfo_swoole_void
#ifdef SW_USE_OPENSSL
#define arginfo_class_Swoole_Coroutine_Http_Client_getPeerCert   arginfo_swoole_void
#endif
#define arginfo_class_Swoole_Coroutine_Http_Client_upgrade       arginfo_swoole_http_client_coro_upgrade
#define arginfo_class_Swoole_Coroutine_Http_Client_push          arginfo_swoole_http_client_coro_push
#define arginfo_class_Swoole_Coroutine_Http_Client_recv          arginfo_swoole_http_client_coro_recv
#define arginfo_class_Swoole_Coroutine_Http_Client_close         arginfo_swoole_void

