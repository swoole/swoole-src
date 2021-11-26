ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_create, 0, 0, 0)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_parse, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_Http_Request_getContent  arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Request_getData     arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Request_create      arginfo_swoole_http_create
#define arginfo_class_Swoole_Http_Request_parse       arginfo_swoole_http_parse
#define arginfo_class_Swoole_Http_Request_isCompleted arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Request_getMethod   arginfo_swoole_http_void
#define arginfo_class_Swoole_Http_Request___destruct  arginfo_swoole_http_void
