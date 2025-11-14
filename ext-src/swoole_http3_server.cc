/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_http_server.h"

#ifdef SW_USE_HTTP3

#include "swoole_http3.h"
#include "swoole_quic.h"

using namespace swoole;
using namespace swoole::http3;

static zend_class_entry *swoole_http3_server_ce;
static zend_object_handlers swoole_http3_server_handlers;

static zend_class_entry *swoole_http3_request_ce;
static zend_object_handlers swoole_http3_request_handlers;

static zend_class_entry *swoole_http3_response_ce;
static zend_object_handlers swoole_http3_response_handlers;

struct Http3ServerObject {
    http3::Server *server;
    zend_object std;
};

struct Http3RequestObject {
    http3::Stream *stream;
    http3::Connection *conn;
    zend_object std;
};

struct Http3ResponseObject {
    http3::Stream *stream;
    http3::Connection *conn;
    zend_object std;
};

static sw_inline Http3ServerObject* php_swoole_http3_server_fetch_object(zend_object *obj) {
    return (Http3ServerObject *) ((char *) obj - swoole_http3_server_handlers.offset);
}

static sw_inline Http3RequestObject* php_swoole_http3_request_fetch_object(zend_object *obj) {
    return (Http3RequestObject *) ((char *) obj - swoole_http3_request_handlers.offset);
}

static sw_inline Http3ResponseObject* php_swoole_http3_response_fetch_object(zend_object *obj) {
    return (Http3ResponseObject *) ((char *) obj - swoole_http3_response_handlers.offset);
}

// ==================== HTTP/3 Server Methods ====================

static PHP_METHOD(swoole_http3_server, __construct);
static PHP_METHOD(swoole_http3_server, __destruct);
static PHP_METHOD(swoole_http3_server, set);
static PHP_METHOD(swoole_http3_server, on);
static PHP_METHOD(swoole_http3_server, start);

// ==================== HTTP/3 Request Methods ====================

static PHP_METHOD(swoole_http3_request, __construct);
static PHP_METHOD(swoole_http3_request, __destruct);

// ==================== HTTP/3 Response Methods ====================

static PHP_METHOD(swoole_http3_response, __construct);
static PHP_METHOD(swoole_http3_response, __destruct);
static PHP_METHOD(swoole_http3_response, header);
static PHP_METHOD(swoole_http3_response, status);
static PHP_METHOD(swoole_http3_response, write);
static PHP_METHOD(swoole_http3_response, end);

// ==================== Method Argument Info ====================

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_server_construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_server_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_server_on, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, event_name, IS_STRING, 0)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_server_start, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_response_header, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_response_status, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, status_code, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_response_write, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http3_response_end, 0, 0, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 1)
ZEND_END_ARG_INFO()

// ==================== Method Tables ====================

static const zend_function_entry swoole_http3_server_methods[] = {
    PHP_ME(swoole_http3_server, __construct, arginfo_swoole_http3_server_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_server, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_server, set, arginfo_swoole_http3_server_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_server, on, arginfo_swoole_http3_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_server, start, arginfo_swoole_http3_server_start, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_http3_request_methods[] = {
    PHP_ME(swoole_http3_request, __construct, arginfo_swoole_void, ZEND_ACC_PRIVATE)
    PHP_ME(swoole_http3_request, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_http3_response_methods[] = {
    PHP_ME(swoole_http3_response, __construct, arginfo_swoole_void, ZEND_ACC_PRIVATE)
    PHP_ME(swoole_http3_response, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_response, header, arginfo_swoole_http3_response_header, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_response, status, arginfo_swoole_http3_response_status, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_response, write, arginfo_swoole_http3_response_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http3_response, end, arginfo_swoole_http3_response_end, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

// ==================== Object Handlers ====================

static zend_object* swoole_http3_server_create_object(zend_class_entry *ce) {
    Http3ServerObject *hso = (Http3ServerObject *) zend_object_alloc(sizeof(Http3ServerObject), ce);
    zend_object_std_init(&hso->std, ce);
    object_properties_init(&hso->std, ce);
    hso->std.handlers = &swoole_http3_server_handlers;
    hso->server = nullptr;
    return &hso->std;
}

static void swoole_http3_server_free_object(zend_object *object) {
    Http3ServerObject *hso = php_swoole_http3_server_fetch_object(object);
    if (hso->server) {
        delete hso->server;
        hso->server = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object* swoole_http3_request_create_object(zend_class_entry *ce) {
    Http3RequestObject *hro = (Http3RequestObject *) zend_object_alloc(sizeof(Http3RequestObject), ce);
    zend_object_std_init(&hro->std, ce);
    object_properties_init(&hro->std, ce);
    hro->std.handlers = &swoole_http3_request_handlers;
    hro->stream = nullptr;
    hro->conn = nullptr;
    return &hro->std;
}

static void swoole_http3_request_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

static zend_object* swoole_http3_response_create_object(zend_class_entry *ce) {
    Http3ResponseObject *hro = (Http3ResponseObject *) zend_object_alloc(sizeof(Http3ResponseObject), ce);
    zend_object_std_init(&hro->std, ce);
    object_properties_init(&hro->std, ce);
    hro->std.handlers = &swoole_http3_response_handlers;
    hro->stream = nullptr;
    hro->conn = nullptr;
    return &hro->std;
}

static void swoole_http3_response_free_object(zend_object *object) {
    zend_object_std_dtor(object);
}

// ==================== Module Init ====================

void php_swoole_http3_server_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_http3_server, "Swoole\\Http3\\Server", nullptr, swoole_http3_server_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http3_server);
    SW_SET_CLASS_CLONEABLE(swoole_http3_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http3_server, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http3_server, swoole_http3_server_create_object, swoole_http3_server_free_object, Http3ServerObject, std);

    SW_INIT_CLASS_ENTRY(swoole_http3_request, "Swoole\\Http3\\Request", nullptr, swoole_http3_request_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http3_request);
    SW_SET_CLASS_CLONEABLE(swoole_http3_request, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http3_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http3_request, swoole_http3_request_create_object, swoole_http3_request_free_object, Http3RequestObject, std);

    SW_INIT_CLASS_ENTRY(swoole_http3_response, "Swoole\\Http3\\Response", nullptr, swoole_http3_response_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http3_response);
    SW_SET_CLASS_CLONEABLE(swoole_http3_response, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http3_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http3_response, swoole_http3_response_create_object, swoole_http3_response_free_object, Http3ResponseObject, std);

    // Register properties
    zend_declare_property_null(swoole_http3_request_ce, ZEND_STRL("server"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http3_request_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http3_request_ce, ZEND_STRL("get"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http3_request_ce, ZEND_STRL("post"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http3_request_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http3_request_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
}

// ==================== Server Implementation ====================

static PHP_METHOD(swoole_http3_server, __construct) {
    char *host;
    size_t host_len;
    zend_long port;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_LONG(port)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (port < 1 || port > 65535) {
        php_swoole_fatal_error(E_ERROR, "invalid port %ld", port);
        RETURN_FALSE;
    }

    Http3ServerObject *hso = php_swoole_http3_server_fetch_object(Z_OBJ_P(ZEND_THIS));

    hso->server = new http3::Server();
    if (!hso->server) {
        php_swoole_fatal_error(E_ERROR, "failed to create HTTP/3 server");
        RETURN_FALSE;
    }

    // Store host and port for later binding
    zend_update_property_stringl(swoole_http3_server_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http3_server_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("port"), port);
}

static PHP_METHOD(swoole_http3_server, __destruct) {
    Http3ServerObject *hso = php_swoole_http3_server_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (hso->server) {
        hso->server->stop();
        delete hso->server;
        hso->server = nullptr;
    }
}

static PHP_METHOD(swoole_http3_server, set) {
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Http3ServerObject *hso = php_swoole_http3_server_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hso->server) {
        php_swoole_fatal_error(E_WARNING, "server not initialized");
        RETURN_FALSE;
    }

    zval *ztmp;
    HashTable *vht = Z_ARRVAL_P(zset);

    // SSL certificate file
    if (php_swoole_array_get_value(vht, "ssl_cert_file", ztmp)) {
        zend_update_property(swoole_http3_server_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("ssl_cert_file"), ztmp);
    }

    // SSL key file
    if (php_swoole_array_get_value(vht, "ssl_key_file", ztmp)) {
        zend_update_property(swoole_http3_server_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("ssl_key_file"), ztmp);
    }

    // HTTP/3 specific settings
    if (php_swoole_array_get_value(vht, "http3_max_field_section_size", ztmp)) {
        hso->server->max_field_section_size = zval_get_long(ztmp);
    }

    if (php_swoole_array_get_value(vht, "http3_qpack_max_table_capacity", ztmp)) {
        hso->server->qpack_max_table_capacity = zval_get_long(ztmp);
    }

    if (php_swoole_array_get_value(vht, "http3_qpack_blocked_streams", ztmp)) {
        hso->server->qpack_blocked_streams = zval_get_long(ztmp);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http3_server, on) {
    char *event_name;
    size_t event_name_len;
    zval *zcallback;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(event_name, event_name_len)
        Z_PARAM_ZVAL(zcallback)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!zend_is_callable(zcallback, 0, nullptr)) {
        php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", event_name);
        RETURN_FALSE;
    }

    zend_update_property(swoole_http3_server_ce, SW_Z8_OBJ_P(ZEND_THIS), event_name, event_name_len, zcallback);

    RETURN_TRUE;
}

// Helper function to parse cookies
static void parse_cookies(const char *cookie_str, size_t len, zval *zcookie) {
    if (!cookie_str || len == 0) {
        return;
    }

    std::string cookies(cookie_str, len);
    size_t start = 0;

    while (start < cookies.length()) {
        // Skip whitespace
        while (start < cookies.length() && (cookies[start] == ' ' || cookies[start] == '\t')) {
            start++;
        }

        // Find next semicolon
        size_t semi_pos = cookies.find(';', start);
        if (semi_pos == std::string::npos) {
            semi_pos = cookies.length();
        }

        std::string pair = cookies.substr(start, semi_pos - start);
        size_t eq_pos = pair.find('=');

        if (eq_pos != std::string::npos) {
            std::string key = pair.substr(0, eq_pos);
            std::string value = pair.substr(eq_pos + 1);

            // Trim whitespace
            size_t key_start = key.find_first_not_of(" \t");
            size_t key_end = key.find_last_not_of(" \t");
            if (key_start != std::string::npos) {
                key = key.substr(key_start, key_end - key_start + 1);
            }

            add_assoc_stringl(zcookie, (char *) key.c_str(), (char *) value.c_str(), value.length());
        }

        start = semi_pos + 1;
    }
}

static void http3_server_on_request(http3::Connection *conn, http3::Stream *stream) {
    // Get the Server object from connection's user_data
    http3::Server *server = (http3::Server *) conn->user_data;
    if (!server || !server->user_data) {
        return;
    }

    // Get the PHP server object from server's user_data
    zend_object *zserver_obj = (zend_object *) server->user_data;
    zval zserver;
    ZVAL_OBJ(&zserver, zserver_obj);

    // Get the request callback
    zval *zcallback = sw_zend_read_property(swoole_http3_server_ce, &zserver, ZEND_STRL("request"), 0);
    if (!zcallback || ZVAL_IS_NULL(zcallback) || !zend_is_callable(zcallback, 0, nullptr)) {
        php_swoole_error(E_WARNING, "onRequest callback is not callable");
        return;
    }

    // Create Request object
    zval zrequest;
    object_init_ex(&zrequest, swoole_http3_request_ce);
    Http3RequestObject *req_obj = php_swoole_http3_request_fetch_object(Z_OBJ(zrequest));
    req_obj->stream = stream;
    req_obj->conn = conn;

    // Populate Request properties
    zval zserver_info, zheader, zget, zcookie;
    array_init(&zserver_info);
    array_init(&zheader);
    array_init(&zget);
    array_init(&zcookie);

    // Add server info
    add_assoc_string(&zserver_info, "request_method", (char *) stream->method.c_str());
    add_assoc_string(&zserver_info, "request_uri", (char *) stream->path.c_str());
    add_assoc_string(&zserver_info, "path_info", (char *) stream->path.c_str());
    add_assoc_long(&zserver_info, "request_time", time(nullptr));
    add_assoc_string(&zserver_info, "server_protocol", (char *) "HTTP/3");

    // Parse query string from path
    std::string query_string;
    size_t question_pos = stream->path.find('?');
    if (question_pos != std::string::npos) {
        query_string = stream->path.substr(question_pos + 1);
        add_assoc_stringl(&zserver_info, "query_string", (char *) query_string.c_str(), query_string.length());

        // Simple query string parser
        size_t start = 0;
        while (start < query_string.length()) {
            size_t amp_pos = query_string.find('&', start);
            if (amp_pos == std::string::npos) {
                amp_pos = query_string.length();
            }

            std::string pair = query_string.substr(start, amp_pos - start);
            size_t eq_pos = pair.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = pair.substr(0, eq_pos);
                std::string value = pair.substr(eq_pos + 1);
                add_assoc_stringl(&zget, (char *) key.c_str(), (char *) value.c_str(), value.length());
            }

            start = amp_pos + 1;
        }
    }

    // Add headers
    for (const auto &hf : stream->headers) {
        if (hf.name[0] != ':') {  // Skip pseudo-headers
            add_assoc_stringl(&zheader, (char *) hf.name.c_str(), (char *) hf.value.c_str(), hf.value.length());

            // Also add some important headers to server info
            if (strcasecmp(hf.name.c_str(), "host") == 0) {
                add_assoc_stringl(&zserver_info, "http_host", (char *) hf.value.c_str(), hf.value.length());
            } else if (strcasecmp(hf.name.c_str(), "user-agent") == 0) {
                add_assoc_stringl(&zserver_info, "http_user_agent", (char *) hf.value.c_str(), hf.value.length());
            } else if (strcasecmp(hf.name.c_str(), "cookie") == 0) {
                parse_cookies(hf.value.c_str(), hf.value.length(), &zcookie);
            }
        } else if (hf.name == ":authority") {
            add_assoc_stringl(&zserver_info, "http_host", (char *) hf.value.c_str(), hf.value.length());
        }
    }

    // Set request properties
    zend_update_property(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("server"), &zserver_info);
    zend_update_property(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("header"), &zheader);
    zend_update_property(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("get"), &zget);
    zend_update_property(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("cookie"), &zcookie);
    zend_update_property_long(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("streamId"), stream->stream_id);

    // Parse POST data if available
    if (stream->body && stream->body->length > 0) {
        zval zpost;
        array_init(&zpost);
        // For now, just store raw body - could parse application/x-www-form-urlencoded later
        zend_update_property(swoole_http3_request_ce, Z_OBJ(zrequest), ZEND_STRL("post"), &zpost);
        zval_ptr_dtor(&zpost);
    }

    // Create Response object
    zval zresponse;
    object_init_ex(&zresponse, swoole_http3_response_ce);
    Http3ResponseObject *resp_obj = php_swoole_http3_response_fetch_object(Z_OBJ(zresponse));
    resp_obj->stream = stream;
    resp_obj->conn = conn;

    // Call user's request callback
    zval args[2];
    args[0] = zrequest;
    args[1] = zresponse;

    zval retval;
    if (UNEXPECTED(call_user_function(EG(function_table), nullptr, zcallback, &retval, 2, args) != SUCCESS)) {
        php_swoole_error(E_WARNING, "onRequest callback handler error");
    }
    zval_ptr_dtor(&retval);

    // Cleanup
    zval_ptr_dtor(&zserver_info);
    zval_ptr_dtor(&zheader);
    zval_ptr_dtor(&zget);
    zval_ptr_dtor(&zcookie);
    zval_ptr_dtor(&zrequest);
    zval_ptr_dtor(&zresponse);
}

static PHP_METHOD(swoole_http3_server, start) {
    Http3ServerObject *hso = php_swoole_http3_server_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hso->server) {
        php_swoole_fatal_error(E_WARNING, "server not initialized");
        RETURN_FALSE;
    }

    // Get host and port
    zval *zhost = sw_zend_read_property(swoole_http3_server_ce, ZEND_THIS, ZEND_STRL("host"), 0);
    zval *zport = sw_zend_read_property(swoole_http3_server_ce, ZEND_THIS, ZEND_STRL("port"), 0);

    // Get SSL certificate and key
    zval *zcert = sw_zend_read_property(swoole_http3_server_ce, ZEND_THIS, ZEND_STRL("ssl_cert_file"), 0);
    zval *zkey = sw_zend_read_property(swoole_http3_server_ce, ZEND_THIS, ZEND_STRL("ssl_key_file"), 0);

    if (Z_TYPE_P(zcert) != IS_STRING || Z_TYPE_P(zkey) != IS_STRING) {
        php_swoole_fatal_error(E_ERROR, "ssl_cert_file and ssl_key_file are required for HTTP/3");
        RETURN_FALSE;
    }

    // Create SSL context
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx) {
        php_swoole_fatal_error(E_ERROR, "failed to create SSL context");
        RETURN_FALSE;
    }

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ssl_ctx, Z_STRVAL_P(zcert), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        php_swoole_fatal_error(E_ERROR, "failed to load SSL certificate");
        RETURN_FALSE;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, Z_STRVAL_P(zkey), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        php_swoole_fatal_error(E_ERROR, "failed to load SSL private key");
        RETURN_FALSE;
    }

    // Bind server
    if (!hso->server->bind(Z_STRVAL_P(zhost), Z_LVAL_P(zport), ssl_ctx)) {
        SSL_CTX_free(ssl_ctx);
        php_swoole_fatal_error(E_ERROR, "failed to bind HTTP/3 server");
        RETURN_FALSE;
    }

    // Store PHP server object reference for callbacks
    hso->server->user_data = Z_OBJ_P(ZEND_THIS);

    // Set request callback
    hso->server->on_request = http3_server_on_request;

    // Start server
    if (!hso->server->start()) {
        php_swoole_fatal_error(E_ERROR, "failed to start HTTP/3 server");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

// ==================== Request Implementation ====================

static PHP_METHOD(swoole_http3_request, __construct) {
    php_swoole_fatal_error(E_ERROR, "private constructor");
}

static PHP_METHOD(swoole_http3_request, __destruct) {
    // Cleanup
}

// ==================== Response Implementation ====================

static PHP_METHOD(swoole_http3_response, __construct) {
    php_swoole_fatal_error(E_ERROR, "private constructor");
}

static PHP_METHOD(swoole_http3_response, __destruct) {
    // Cleanup
}

static PHP_METHOD(swoole_http3_response, header) {
    char *key, *value;
    size_t key_len, value_len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(key, key_len)
        Z_PARAM_STRING(value, value_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Http3ResponseObject *hro = php_swoole_http3_response_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hro->stream) {
        php_swoole_fatal_error(E_WARNING, "stream not available");
        RETURN_FALSE;
    }

    hro->stream->add_header(std::string(key, key_len), std::string(value, value_len));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http3_response, status) {
    zend_long status_code;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(status_code)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (status_code < 100 || status_code > 599) {
        php_swoole_fatal_error(E_WARNING, "invalid HTTP status code %ld", status_code);
        RETURN_FALSE;
    }

    Http3ResponseObject *hro = php_swoole_http3_response_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hro->stream) {
        php_swoole_fatal_error(E_WARNING, "stream not available");
        RETURN_FALSE;
    }

    hro->stream->status_code = status_code;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http3_response, write) {
    char *data;
    size_t data_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Http3ResponseObject *hro = php_swoole_http3_response_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hro->stream) {
        php_swoole_fatal_error(E_WARNING, "stream not available");
        RETURN_FALSE;
    }

    if (!hro->stream->send_body((const uint8_t *) data, data_len, false)) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http3_response, end) {
    char *data = nullptr;
    size_t data_len = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Http3ResponseObject *hro = php_swoole_http3_response_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (!hro->stream) {
        php_swoole_fatal_error(E_WARNING, "stream not available");
        RETURN_FALSE;
    }

    // Build response headers
    std::vector<HeaderField> headers;
    headers.emplace_back(":status", std::to_string(hro->stream->status_code > 0 ? hro->stream->status_code : 200));

    // Add custom headers
    for (const auto &hf : hro->stream->headers) {
        if (hf.name[0] != ':') {  // Skip pseudo-headers
            headers.push_back(hf);
        }
    }

    // Send response
    if (!hro->stream->send_response(hro->stream->status_code > 0 ? hro->stream->status_code : 200,
                                      headers,
                                      (const uint8_t *) data,
                                      data_len)) {
        RETURN_FALSE;
    }

    // Write queued data
    if (hro->conn) {
        hro->conn->write_streams();
    }

    RETURN_TRUE;
}

#endif // SW_USE_HTTP3
