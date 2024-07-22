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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */
#include "php_swoole_http_server.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_http_cookie_arginfo.h"
END_EXTERN_C()

using HttpCookie = swoole::http::Cookie;

zend_class_entry *swoole_http_cookie_ce;
static zend_object_handlers swoole_http_cookie_handlers;

struct HttpCookieObject {
    HttpCookie *cookie;
    zend_object std;
};

static sw_inline HttpCookieObject *php_swoole_http_cookie_fetch_object(zend_object *obj) {
    return (HttpCookieObject *) ((char *) obj - swoole_http_cookie_handlers.offset);
}

HttpCookie *php_swoole_http_get_cookie(zval *zobject) {
    return php_swoole_http_cookie_fetch_object(Z_OBJ_P(zobject))->cookie;
}

HttpCookie *php_swoole_http_response_get_and_check_cookie(zval *zobject) {
    HttpCookie *cookie = php_swoole_http_get_cookie(zobject);
    if (!cookie) {
        swoole_set_last_error(SW_ERROR_HTTP_COOKIE_UNAVAILABLE);
        return nullptr;
    }

    return cookie;
}

void php_swoole_http_response_set_cookie(zval *zobject, HttpCookie *cookie) {
    php_swoole_http_cookie_fetch_object(Z_OBJ_P(zobject))->cookie = cookie;
}

static zend_object *php_swoole_http_cookie_create_object(zend_class_entry *ce) {
    HttpCookieObject *httpCookieObject = (HttpCookieObject *) zend_object_alloc(sizeof(HttpCookieObject), ce);
    zend_object_std_init(&httpCookieObject->std, ce);
    object_properties_init(&httpCookieObject->std, ce);
    httpCookieObject->std.handlers = &swoole_http_cookie_handlers;
    return &httpCookieObject->std;
}

static void php_swoole_http_cookie_free_object(zend_object *object) {
    HttpCookieObject *httpCookieObject = php_swoole_http_cookie_fetch_object(object);
    delete httpCookieObject->cookie;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http_cookie, __construct);
static PHP_METHOD(swoole_http_cookie, withName);
static PHP_METHOD(swoole_http_cookie, withValue);
static PHP_METHOD(swoole_http_cookie, withExpires);
static PHP_METHOD(swoole_http_cookie, withPath);
static PHP_METHOD(swoole_http_cookie, withDomain);
static PHP_METHOD(swoole_http_cookie, withSecure);
static PHP_METHOD(swoole_http_cookie, withHttpOnly);
static PHP_METHOD(swoole_http_cookie, withSameSite);
static PHP_METHOD(swoole_http_cookie, withPriority);
static PHP_METHOD(swoole_http_cookie, withPartitioned);
static PHP_METHOD(swoole_http_cookie, withUrlEncode);
static PHP_METHOD(swoole_http_cookie, getCookie);
static PHP_METHOD(swoole_http_cookie, reset);
SW_EXTERN_C_END

// clang-format off
const zend_function_entry swoole_http_cookie_methods[] =
{
    PHP_ME(swoole_http_cookie, __construct,     arginfo_class_Swoole_Http_Cookie___construct,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withName,         arginfo_class_Swoole_Http_Cookie_withName,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withValue,        arginfo_class_Swoole_Http_Cookie_withValue,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withExpires,      arginfo_class_Swoole_Http_Cookie_withExpires,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withPath,         arginfo_class_Swoole_Http_Cookie_withPath,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withDomain,       arginfo_class_Swoole_Http_Cookie_withDomain,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withSecure,       arginfo_class_Swoole_Http_Cookie_withSecure,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withHttpOnly,     arginfo_class_Swoole_Http_Cookie_withHttpOnly,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withSameSite,     arginfo_class_Swoole_Http_Cookie_withSameSite,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withPriority,     arginfo_class_Swoole_Http_Cookie_withPriority,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, withPartitioned,  arginfo_class_Swoole_Http_Cookie_withPartitioned,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, getCookie,       arginfo_class_Swoole_Http_Cookie_getCookie,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, reset,           arginfo_class_Swoole_Http_Cookie_reset,             ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_http_cookie_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_http_cookie, "Swoole\\Http\\Cookie", nullptr, swoole_http_cookie_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_cookie);
    SW_SET_CLASS_CLONEABLE(swoole_http_cookie, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_cookie, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_cookie,
                               php_swoole_http_cookie_create_object,
                               php_swoole_http_cookie_free_object,
                               HttpCookieObject,
                               std);
}

static PHP_METHOD(swoole_http_cookie, __construct) {
    php_swoole_http_response_set_cookie(ZEND_THIS, new HttpCookie());
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_cookie, withName) {
    zend_string *name = nullptr;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->name) {
        zend_string_release(cookie->name);
        cookie->name = nullptr;
    }

    zend_string_addref(name);
    cookie->name = name;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withValue) {
    zend_string *value = nullptr;
    zend_bool encode = true;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(value)
        Z_PARAM_BOOL(encode)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->value) {
        zend_string_release(cookie->value);
        cookie->value = nullptr;
        cookie->encode = true;
    }

    if (value && ZSTR_LEN(value) > 0) {
        zend_string_addref(value);
        cookie->value = value;
        cookie->encode = encode;
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withExpires) {
    zend_long expires = 0;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(expires)
    ZEND_PARSE_PARAMETERS_END();

    cookie->expires = expires;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withPath) {
    zend_string *path = nullptr;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(path)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->path) {
        zend_string_release(cookie->path);
        cookie->path = nullptr;
    }

    zend_string_addref(path);
    cookie->path = path;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withDomain) {
    zend_string *domain = nullptr;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(domain)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->domain) {
        zend_string_release(cookie->domain);
        cookie->domain = nullptr;
    }

    zend_string_addref(domain);
    cookie->domain = domain;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withSecure) {
    zend_bool secure = false;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(secure)
    ZEND_PARSE_PARAMETERS_END();

    cookie->secure = secure;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withHttpOnly) {
    zend_bool httpOnly = false;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(httpOnly)
    ZEND_PARSE_PARAMETERS_END();

    cookie->httpOnly = httpOnly;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withSameSite) {
    zend_string *sameSite = nullptr;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(sameSite)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->sameSite) {
        zend_string_release(cookie->sameSite);
        cookie->sameSite = nullptr;
    }

    zend_string_addref(sameSite);
    cookie->sameSite = sameSite;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withPriority) {
    zend_string *priority = nullptr;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(priority)
    ZEND_PARSE_PARAMETERS_END();

    if (cookie->priority) {
        zend_string_release(cookie->priority);
        cookie->priority = nullptr;
    }

    zend_string_addref(priority);
    cookie->priority = priority;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withPartitioned) {
    zend_bool partitioned = false;
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(partitioned)
    ZEND_PARSE_PARAMETERS_END();

    cookie->partitioned = partitioned;
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, getCookie) {
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_NONE();

    array_init(return_value);
    cookie->name ? add_assoc_str(return_value, "name", cookie->name) : add_assoc_string(return_value, "name", "");
    cookie->value ? add_assoc_str(return_value, "value", cookie->value) : add_assoc_string(return_value, "value", "");
    cookie->domain ? add_assoc_str(return_value, "domain", cookie->path) : add_assoc_string(return_value, "domain", "");
    cookie->sameSite ? add_assoc_str(return_value, "sameSite", cookie->name) : add_assoc_string(return_value, "sameSite", "");
    cookie->priority ? add_assoc_str(return_value, "priority", cookie->name) : add_assoc_string(return_value, "priority", "");
    add_assoc_bool(return_value, "encode", cookie->encode);
    add_assoc_long(return_value, "expires", cookie->expires);
    add_assoc_bool(return_value, "secure", cookie->secure);
    add_assoc_bool(return_value, "httpOnly", cookie->httpOnly);
    add_assoc_bool(return_value, "partitioned", cookie->partitioned);
}

static PHP_METHOD(swoole_http_cookie, reset) {
    HttpCookie *cookie = php_swoole_http_get_cookie(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_NONE();

    cookie->expires = 0;
    cookie->secure = false;
    cookie->httpOnly = false;
    cookie->partitioned = false;
    cookie->encode = true;

    if (cookie->name) {
        zend_string_release(cookie->name);
        cookie->name = nullptr;
    }

    if (cookie->value) {
        zend_string_release(cookie->value);
        cookie->value = nullptr;
    }

    if (cookie->path) {
        zend_string_release(cookie->path);
        cookie->path = nullptr;
    }

    if (cookie->domain) {
        zend_string_release(cookie->domain);
        cookie->domain = nullptr;
    }

    if (cookie->sameSite) {
        zend_string_release(cookie->sameSite);
        cookie->sameSite = nullptr;
    }

    if (cookie->priority) {
        zend_string_release(cookie->priority);
        cookie->priority = nullptr;
    }

    RETURN_TRUE;
}
