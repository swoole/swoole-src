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

#define ILLEGAL_COOKIE_CHARACTER_PRINT "\",\", \";\", \" \", \"\\t\", \"\\r\", \"\\n\", \"\\013\", or \"\\014\""
#define ILLEGAL_COOKIE_CHARACTER ",; \t\r\n\013\014"

static const zend_long maxValidSeconds = 253402300800;

zend_class_entry *swoole_http_cookie_ce;
static zend_object_handlers swoole_http_cookie_handlers;

struct HttpCookieObject {
    HttpCookie *cookie;
    zend_object std;
};

static sw_inline HttpCookieObject *php_swoole_http_cookie_fetch_object(zend_object *obj) {
    return (HttpCookieObject *) ((char *) obj - swoole_http_cookie_handlers.offset);
}

static HttpCookie *php_swoole_http_get_cookie(zval *zobject) {
    return php_swoole_http_cookie_fetch_object(Z_OBJ_P(zobject))->cookie;
}

HttpCookie *php_swoole_http_get_cooke_safety(zval *zobject) {
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
static PHP_METHOD(swoole_http_cookie, toArray);
static PHP_METHOD(swoole_http_cookie, toString);
static PHP_METHOD(swoole_http_cookie, reset);
SW_EXTERN_C_END

// clang-format off
const zend_function_entry swoole_http_cookie_methods[] =
{
    PHP_ME(swoole_http_cookie, __construct,      arginfo_class_Swoole_Http_Cookie___construct,        ZEND_ACC_PUBLIC)
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
    PHP_ME(swoole_http_cookie, toString,         arginfo_class_Swoole_Http_Cookie_toString,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, toArray,          arginfo_class_Swoole_Http_Cookie_toArray,            ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_cookie, reset,            arginfo_class_Swoole_Http_Cookie_reset,              ZEND_ACC_PUBLIC)
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

#define HTTP_COOKIE_WITH_STR(field)                                                                                    \
    if (field) {                                                                                                       \
        zend_string_release(field);                                                                                    \
    }                                                                                                                  \
    if (_##field && ZSTR_LEN(_##field) > 0) {                                                                          \
        zend_string_addref(_##field);                                                                                  \
        field = _##field;                                                                                              \
    } else {                                                                                                           \
        field = nullptr;                                                                                               \
    }                                                                                                                  \
    return this;

HttpCookie *HttpCookie::withName(zend_string *_name) {
    HTTP_COOKIE_WITH_STR(name);
}

HttpCookie *HttpCookie::withValue(zend_string *_value) {
    HTTP_COOKIE_WITH_STR(value);
}

HttpCookie *HttpCookie::withDomain(zend_string *_domain) {
    HTTP_COOKIE_WITH_STR(domain);
}

HttpCookie *HttpCookie::withPath(zend_string *_path) {
    HTTP_COOKIE_WITH_STR(path);
}

HttpCookie *HttpCookie::withSameSite(zend_string *_sameSite) {
    HTTP_COOKIE_WITH_STR(sameSite);
}

HttpCookie *HttpCookie::withPriority(zend_string *_priority) {
    HTTP_COOKIE_WITH_STR(priority);
}

HttpCookie *HttpCookie::withExpires(zend_long _expires) {
    expires = _expires;
    return this;
}

HttpCookie *HttpCookie::withSecure(zend_bool _secure) {
    secure = _secure;
    return this;
}

HttpCookie *HttpCookie::withHttpOnly(zend_bool _httpOnly) {
    httpOnly = _httpOnly;
    return this;
}

HttpCookie *HttpCookie::withPartitioned(zend_bool _partitioned) {
    partitioned = _partitioned;
    return this;
}

zend_string *HttpCookie::toString() {
    zend_string *date = nullptr;
    if (name == nullptr || ZSTR_LEN(name) == 0) {
        php_swoole_error(E_WARNING, "The name cannot be empty");
        return nullptr;
    }

    if (strpbrk(ZSTR_VAL(name), "=" ILLEGAL_COOKIE_CHARACTER) != nullptr) {
        php_swoole_error(E_WARNING, "The name cannot contain \"=\", " ILLEGAL_COOKIE_CHARACTER_PRINT);
        return nullptr;
    }

    smart_str_append(&buffer_, name);

    if (!value) {
        smart_str_appends(&buffer_, "=deleted; expires=");

        date = php_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), 1, 0);
        smart_str_append(&buffer_, date);
        smart_str_appends(&buffer_, "; Max-Age=0");
        zend_string_free(date);
    } else {
        if (!encode_ && strpbrk(ZSTR_VAL(value), ILLEGAL_COOKIE_CHARACTER) != nullptr) {
            php_swoole_error(E_WARNING, "The value cannot contain " ILLEGAL_COOKIE_CHARACTER_PRINT);
            return nullptr;
        }

        smart_str_appendc(&buffer_, '=');

        if (encode_) {
            zend_string *encoded_value = php_url_encode(ZSTR_VAL(value), ZSTR_LEN(value));
            smart_str_append(&buffer_, encoded_value);
            zend_string_free(encoded_value);
        } else {
            smart_str_append(&buffer_, value);
        }

        if (expires > 0) {
            if (expires >= maxValidSeconds) {
                php_swoole_error(E_WARNING, "The expires cannot have a year greater than 9999");
                return nullptr;
            }
            smart_str_appends(&buffer_, "; expires=");
            date = php_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), expires, 0);
            smart_str_append(&buffer_, date);
            smart_str_appends(&buffer_, "; Max-Age=");

            double diff = difftime(expires, php_time());
            smart_str_append_long(&buffer_, (zend_long) (diff >= 0 ? diff : 0));
            zend_string_free(date);
        }

        if (path && ZSTR_LEN(path) > 0) {
            if (strpbrk(ZSTR_VAL(path), ILLEGAL_COOKIE_CHARACTER) != NULL) {
                php_swoole_error(E_WARNING, "The path option cannot contain " ILLEGAL_COOKIE_CHARACTER_PRINT);
                return nullptr;
            }
            smart_str_appends(&buffer_, "; path=");
            smart_str_append(&buffer_, path);
        }

        if (domain && ZSTR_LEN(domain) > 0) {
            if (strpbrk(ZSTR_VAL(domain), ILLEGAL_COOKIE_CHARACTER) != NULL) {
                php_swoole_error(E_WARNING, "The domain option cannot contain " ILLEGAL_COOKIE_CHARACTER_PRINT);
                return nullptr;
            }
            smart_str_appends(&buffer_, "; domain=");
            smart_str_append(&buffer_, domain);
        }

        if (secure) {
            smart_str_appends(&buffer_, "; secure");
        }

        if (httpOnly) {
            smart_str_appends(&buffer_, "; HttpOnly");
        }

        if (sameSite && ZSTR_LEN(sameSite) > 0) {
            smart_str_appends(&buffer_, "; SameSite=");
            smart_str_append(&buffer_, sameSite);
        }

        if (priority && ZSTR_LEN(priority) > 0) {
            smart_str_appends(&buffer_, "; Priority=");
            smart_str_append(&buffer_, priority);
        }

        if (partitioned) {
            smart_str_appends(&buffer_, "; Partitioned");
        }
    }

    return smart_str_extract(&buffer_);
}

void HttpCookie::reset() {
    expires = 0;
    secure = false;
    httpOnly = false;
    partitioned = false;
    encode_ = true;

    if (name) {
        zend_string_release(name);
        name = nullptr;
    }

    if (value) {
        zend_string_release(value);
        value = nullptr;
    }

    if (path) {
        zend_string_release(path);
        path = nullptr;
    }

    if (domain) {
        zend_string_release(domain);
        domain = nullptr;
    }

    if (sameSite) {
        zend_string_release(sameSite);
        sameSite = nullptr;
    }

    if (priority) {
        zend_string_release(priority);
        priority = nullptr;
    }

    smart_str_free_ex(&buffer_, false);
}

#define HTTP_COOKIE_ADD_STR_TO_ARRAY(field)                                                                            \
    if (field) {                                                                                                       \
        add_assoc_str(return_value, #field, field);                                                                    \
    } else {                                                                                                           \
        add_assoc_string(return_value, #field, "");                                                                    \
    }

void HttpCookie::toArray(zval *return_value) {
    array_init(return_value);

    HTTP_COOKIE_ADD_STR_TO_ARRAY(name);
    HTTP_COOKIE_ADD_STR_TO_ARRAY(value);
    HTTP_COOKIE_ADD_STR_TO_ARRAY(path);
    HTTP_COOKIE_ADD_STR_TO_ARRAY(domain);
    HTTP_COOKIE_ADD_STR_TO_ARRAY(sameSite);
    HTTP_COOKIE_ADD_STR_TO_ARRAY(priority);

    add_assoc_bool(return_value, "encode", encode_);
    add_assoc_long(return_value, "expires", expires);
    add_assoc_bool(return_value, "secure", secure);
    add_assoc_bool(return_value, "httpOnly", httpOnly);
    add_assoc_bool(return_value, "partitioned", partitioned);
}

HttpCookie::~Cookie() {
    reset();
}

static PHP_METHOD(swoole_http_cookie, __construct) {
    zend_bool encode = true;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(encode)
    ZEND_PARSE_PARAMETERS_END();

    php_swoole_http_response_set_cookie(ZEND_THIS, new HttpCookie(encode));
}

#define PHP_METHOD_HTTP_COOKIE_WITH_STR(field)                                                                         \
    zend_string *field;                                                                                                \
    HttpCookie *cookie = php_swoole_http_get_cooke_safety(ZEND_THIS);                                                  \
                                                                                                                       \
    ZEND_PARSE_PARAMETERS_START(1, 1)                                                                                  \
    Z_PARAM_STR(field)                                                                                                 \
    ZEND_PARSE_PARAMETERS_END();                                                                                       \
                                                                                                                       \
    cookie->with##field(field);                                                                                        \
    RETURN_ZVAL(ZEND_THIS, 1, 0);

#define PHP_METHOD_HTTP_COOKIE_WITH_BOOL(field)                                                                        \
    zend_bool field = false;                                                                                           \
    HttpCookie *cookie = php_swoole_http_get_cooke_safety(ZEND_THIS);                                                  \
                                                                                                                       \
    ZEND_PARSE_PARAMETERS_START(0, 1)                                                                                  \
    Z_PARAM_OPTIONAL                                                                                                   \
    Z_PARAM_BOOL(field)                                                                                                \
    ZEND_PARSE_PARAMETERS_END();                                                                                       \
                                                                                                                       \
    cookie->with##field(field);                                                                                        \
    RETURN_ZVAL(ZEND_THIS, 1, 0);

static PHP_METHOD(swoole_http_cookie, withName) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(Name);
}

static PHP_METHOD(swoole_http_cookie, withValue) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(Value);
}

static PHP_METHOD(swoole_http_cookie, withExpires) {
    zend_long expires = 0;
    HttpCookie *cookie = php_swoole_http_get_cooke_safety(ZEND_THIS);

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(expires)
    ZEND_PARSE_PARAMETERS_END();

    cookie->withExpires(expires);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

static PHP_METHOD(swoole_http_cookie, withPath) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(Path);
}

static PHP_METHOD(swoole_http_cookie, withDomain) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(Domain);
}

static PHP_METHOD(swoole_http_cookie, withSecure) {
    PHP_METHOD_HTTP_COOKIE_WITH_BOOL(Secure);
}

static PHP_METHOD(swoole_http_cookie, withHttpOnly) {
    PHP_METHOD_HTTP_COOKIE_WITH_BOOL(HttpOnly);
}

static PHP_METHOD(swoole_http_cookie, withSameSite) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(SameSite);
}

static PHP_METHOD(swoole_http_cookie, withPriority) {
    PHP_METHOD_HTTP_COOKIE_WITH_STR(Priority);
}

static PHP_METHOD(swoole_http_cookie, withPartitioned) {
    PHP_METHOD_HTTP_COOKIE_WITH_BOOL(Partitioned);
}

static PHP_METHOD(swoole_http_cookie, toString) {
    auto cookie = php_swoole_http_get_cooke_safety(ZEND_THIS);
    auto cookie_str = cookie->toString();
    if (!cookie_str) {
        cookie->reset();
        RETURN_FALSE;
    }
    ZVAL_STR(return_value, cookie_str);
}

static PHP_METHOD(swoole_http_cookie, toArray) {
    php_swoole_http_get_cooke_safety(ZEND_THIS)->toArray(return_value);
}

static PHP_METHOD(swoole_http_cookie, reset) {
    php_swoole_http_get_cooke_safety(ZEND_THIS)->reset();
}
