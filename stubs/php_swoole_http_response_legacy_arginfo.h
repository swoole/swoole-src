ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_status, 0, 0, 1)
    ZEND_ARG_INFO(0, http_code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_header, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, format)
ZEND_END_ARG_INFO()

#ifdef SW_USE_HTTP2
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_trailer, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_cookie, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, expires)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, secure)
    ZEND_ARG_INFO(0, httponly)
    ZEND_ARG_INFO(0, samesite)
    ZEND_ARG_INFO(0, priority)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_write, 0, 0, 1)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_end, 0, 0, 0)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_redirect, 0, 0, 1)
    ZEND_ARG_INFO(0, location)
    ZEND_ARG_INFO(0, http_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_create, 0, 0, 1)
    ZEND_ARG_INFO(0, server)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_goaway, 0, 0, 1)
    ZEND_ARG_INFO(0, error_code)
    ZEND_ARG_INFO(0, debug_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Http_Response_initHeader arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response_isWritable arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response_cookie     arginfo_swoole_http_response_cookie
#define arginfo_class_Swoole_Http_Response_status     arginfo_swoole_http_response_status
#define arginfo_class_Swoole_Http_Response_header     arginfo_swoole_http_response_header
#ifdef SW_USE_HTTP2
#define arginfo_class_Swoole_Http_Response_trailer    arginfo_swoole_http_response_trailer
#define arginfo_class_Swoole_Http_Response_ping       arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response_goaway     arginfo_swoole_http_goaway
#endif
#define arginfo_class_Swoole_Http_Response_write      arginfo_swoole_http_response_write
#define arginfo_class_Swoole_Http_Response_end        arginfo_swoole_http_response_end
#define arginfo_class_Swoole_Http_Response_sendfile   arginfo_swoole_http_response_sendfile
#define arginfo_class_Swoole_Http_Response_redirect   arginfo_swoole_http_response_redirect
#define arginfo_class_Swoole_Http_Response_detach     arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response_create     arginfo_swoole_http_response_create
#define arginfo_class_Swoole_Http_Response_upgrade    arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response_push       arginfo_swoole_http_response_push
#define arginfo_class_Swoole_Http_Response_recv       arginfo_swoole_http_recv
#define arginfo_class_Swoole_Http_Response_close      arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Response___destruct arginfo_swoole_http_void
