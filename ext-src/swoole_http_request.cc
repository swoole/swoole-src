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

SW_EXTERN_C_BEGIN
#include "ext/standard/url.h"
SW_EXTERN_C_END

#include "main/php_variables.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_HAVE_BROTLI
#include <brotli/encode.h>
#endif

enum http_upload_errno {
    HTTP_UPLOAD_ERR_OK = 0,
    HTTP_UPLOAD_ERR_INI_SIZE,
    HTTP_UPLOAD_ERR_FORM_SIZE,
    HTTP_UPLOAD_ERR_PARTIAL,
    HTTP_UPLOAD_ERR_NO_FILE,
    HTTP_UPLOAD_ERR_NO_TMP_DIR = 6,
    HTTP_UPLOAD_ERR_CANT_WRITE,
};

using HttpRequest = swoole::http::Request;
using HttpContext = swoole::http::Context;
using swoole::Connection;
using swoole::ListenPort;
using swoole::microtime;
using swoole::Server;

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(swoole_http_parser *parser);
static int http_request_message_complete(swoole_http_parser *parser);

static int multipart_body_on_header_field(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_header_value(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_data(multipart_parser *p, const char *at, size_t length);
static int multipart_body_on_header_complete(multipart_parser *p);
static int multipart_body_on_data_end(multipart_parser *p);

static int http_request_on_path(swoole_http_parser *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    ctx->request.path = estrndup(at, length);
    ctx->request.path_len = length;
    return 0;
}

static inline char *http_trim_double_quote(char *ptr, size_t *len) {
    size_t i;
    char *tmp = ptr;

    // ltrim('"')
    for (i = 0; i < *len; i++) {
        if (tmp[0] == '"') {
            (*len)--;
            tmp++;
            continue;
        } else {
            break;
        }
    }
    // rtrim('"')
    for (i = (*len); i > 0; i--) {
        if (tmp[i - 1] == '"') {
            tmp[i - 1] = 0;
            (*len)--;
            continue;
        } else {
            break;
        }
    }
    return tmp;
}

static sw_inline const char *http_get_method_name(enum swoole_http_method method) {
    return swoole_http_method_str(method);
}

// clang-format off
static const swoole_http_parser_settings http_parser_settings =
{
    nullptr,
    http_request_on_path,
    http_request_on_query_string,
    nullptr,
    nullptr,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
    http_request_on_body,
    http_request_message_complete
};

static const multipart_parser_settings mt_parser_settings =
{
    multipart_body_on_header_field,
    multipart_body_on_header_value,
    multipart_body_on_data,
    nullptr,
    multipart_body_on_header_complete,
    multipart_body_on_data_end,
    nullptr,
};
// clang-format on

size_t HttpContext::parse(const char *data, size_t length) {
    return swoole_http_parser_execute(&parser, &http_parser_settings, data, length);
}

bool HttpContext::parse_multipart_data(const char *at, size_t length) {
    ssize_t n = multipart_parser_execute(mt_parser, at, length);
    if (n < 0) {
        int l_error = multipart_parser_error_msg(mt_parser, sw_tg_buffer()->str, sw_tg_buffer()->size);
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_INVALID_REQUEST,
                         "parse multipart body failed, reason: %.*s",
                         l_error,
                         sw_tg_buffer()->str);
        return false;
    } else if (n != (ssize_t) length) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_INVALID_REQUEST,
                         "parse multipart body failed, %lu/%zu bytes processed",
                         n,
                         length);
        return false;
    }
    return true;
}

zend_class_entry *swoole_http_request_ce;
static zend_object_handlers swoole_http_request_handlers;

typedef struct {
    HttpContext *ctx;
    zend_object std;
} http_request_t;

static sw_inline http_request_t *php_swoole_http_request_fetch_object(zend_object *obj) {
    return (http_request_t *) ((char *) obj - swoole_http_request_handlers.offset);
}

HttpContext *php_swoole_http_request_get_context(zval *zobject) {
    return php_swoole_http_request_fetch_object(Z_OBJ_P(zobject))->ctx;
}

void php_swoole_http_request_set_context(zval *zobject, HttpContext *ctx) {
    php_swoole_http_request_fetch_object(Z_OBJ_P(zobject))->ctx = ctx;
}

static void php_swoole_http_request_free_object(zend_object *object) {
    http_request_t *request = php_swoole_http_request_fetch_object(object);
    HttpContext *ctx = request->ctx;
    zval zobject, *ztmpfiles;

    ZVAL_OBJ(&zobject, object);
    ztmpfiles = sw_zend_read_property_ex(swoole_http_request_ce, &zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TMPFILES), 0);
    if (ZVAL_IS_ARRAY(ztmpfiles)) {
        zval *z_file_path;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(ztmpfiles), z_file_path) {
            if (Z_TYPE_P(z_file_path) != IS_STRING) {
                continue;
            }
            unlink(Z_STRVAL_P(z_file_path));
            if (SG(rfc1867_uploaded_files)) {
                zend_hash_str_del(SG(rfc1867_uploaded_files), Z_STRVAL_P(z_file_path), Z_STRLEN_P(z_file_path));
            }
        }
        SW_HASHTABLE_FOREACH_END();
    }
    if (ctx) {
        ctx->request.zobject = nullptr;
        ctx->free();
    }

    zend_object_std_dtor(&request->std);
}

static zend_object *php_swoole_http_request_create_object(zend_class_entry *ce) {
    http_request_t *request = (http_request_t *) zend_object_alloc(sizeof(http_request_t), ce);
    zend_object_std_init(&request->std, ce);
    object_properties_init(&request->std, ce);
    request->std.handlers = &swoole_http_request_handlers;
    return &request->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http_request, getData);
static PHP_METHOD(swoole_http_request, create);
static PHP_METHOD(swoole_http_request, parse);
static PHP_METHOD(swoole_http_request, isCompleted);
static PHP_METHOD(swoole_http_request, getMethod);
static PHP_METHOD(swoole_http_request, getContent);
static PHP_METHOD(swoole_http_request, __destruct);
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_create, 0, 0, 0)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_parse, 0, 0, 1)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_http_request_methods[] =
{
    PHP_ME(swoole_http_request, getContent, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_http_request, rawContent, getContent, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, getData, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, create, arginfo_swoole_http_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_http_request, parse, arginfo_swoole_http_parse, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, isCompleted, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, getMethod, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_request, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_http_request_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_http_request, "Swoole\\Http\\Request", "swoole_http_request", nullptr, swoole_http_request_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_request);
    SW_SET_CLASS_CLONEABLE(swoole_http_request, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_request,
                               php_swoole_http_request_create_object,
                               php_swoole_http_request_free_object,
                               http_request_t,
                               std);

    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
#ifdef SW_USE_HTTP2
    zend_declare_property_long(swoole_http_request_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
#endif
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("server"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("get"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("files"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("post"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_request_ce, ZEND_STRL("tmpfiles"), ZEND_ACC_PUBLIC);
}

static int http_request_on_query_string(swoole_http_parser *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    add_assoc_stringl_ex(ctx->request.zserver, ZEND_STRL("query_string"), (char *) at, length);
    // parse url params
    sapi_module.treat_data(PARSE_STRING,
                           estrndup(at, length),  // it will be freed by treat_data
                           swoole_http_init_and_read_property(
                               swoole_http_request_ce, ctx->request.zobject, &ctx->request.zget, ZEND_STRL("get")));
    return 0;
}

static int http_request_on_header_field(swoole_http_parser *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    ctx->current_header_name = (char *) at;
    ctx->current_header_name_len = length;
    return 0;
}

bool HttpContext::init_multipart_parser(const char *boundary_str, int boundary_len) {
    mt_parser = multipart_parser_init(boundary_str, boundary_len, &mt_parser_settings);
    if (!mt_parser) {
        php_swoole_fatal_error(E_WARNING, "multipart_parser_init() failed");
        return false;
    }
    form_data_buffer = new String(SW_BUFFER_SIZE_STD);
    mt_parser->data = this;
    return true;
}

bool HttpContext::get_form_data_boundary(
    const char *at, size_t length, size_t offset, char **out_boundary_str, int *out_boundary_len) {
    while (offset < length) {
        if (at[offset] == ' ' || at[offset] == ';') {
            offset++;
            continue;
        }
        if (SW_STRCASECT(at + offset, length - offset, "boundary=")) {
            offset += sizeof("boundary=") - 1;
            break;
        }
        void *delimiter = memchr((void *) (at + offset), ';', length - offset);
        if (delimiter == nullptr) {
            swoole_warning("boundary of multipart/form-data not found, fd:%ld", fd);
            /* make it same with protocol error */
            parser.state = s_dead;
            return false;
        } else {
            offset += (const char *) delimiter - (at + offset);
        }
    }

    int boundary_len = length - offset;
    char *boundary_str = (char *) at + offset;
    // find eof of boundary
    if (boundary_len > 0) {
        // find ';'
        char *tmp = (char *) memchr(boundary_str, ';', boundary_len);
        if (tmp) {
            boundary_len = tmp - boundary_str;
        }
    }
    if (boundary_len <= 0) {
        swoole_warning("invalid multipart/form-data body fd:%ld", fd);
        /* make it same with protocol error */
        parser.state = s_dead;
        return false;
    }
    // trim '"'
    if (boundary_len >= 2 && boundary_str[0] == '"' && *(boundary_str + boundary_len - 1) == '"') {
        boundary_str++;
        boundary_len -= 2;
    }
    *out_boundary_str = boundary_str;
    *out_boundary_len = boundary_len;
    return true;
}

void swoole_http_parse_cookie(zval *zarray, const char *at, size_t length) {
    if (length == 0) {
        return;
    }

    char *var, *val;
    const char *separator = ";\0";
    zend_long count = 0;
    size_t var_len = 0;
    char *strtok_buf = nullptr;

    char *_c = sw_tg_buffer()->str;
    memcpy(_c, at, length);
    _c[length] = '\0';

    var = php_strtok_r(_c, separator, &strtok_buf);
    while (var) {
        size_t val_len;
        val = strchr(var, '=');

        while (isspace(*var)) {
            var++;
        }

        if (var == val || *var == '\0') {
            goto next_cookie;
        }

        if (++count > PG(max_input_vars)) {
            swoole_warning("Input variables exceeded " ZEND_LONG_FMT
                           ". To increase the limit change max_input_vars in php.ini.",
                           PG(max_input_vars));
            break;
        }

        if (val) { /* have a value */
            *val++ = '\0';
            val_len = php_raw_url_decode(val, strlen(val));
        } else {
            val = (char *) "";
            val_len = 0;
        }

        var_len = strlen(var);
        add_assoc_stringl_ex(zarray, var, var_len, val, val_len);
    next_cookie:
        var = php_strtok_r(NULL, separator, &strtok_buf);
    }
}

bool swoole_http_token_list_contains_value(const char *at, size_t length, const char *value) {
    if (0 == length) {
        return false;
    }
    if (SW_STRCASEEQ(at, length, value)) {
        return true;
    }

    char *var;
    const char *separator = ",\0";
    char *strtok_buf = nullptr;
    size_t var_len;

    char *_c = sw_tg_buffer()->str;
    memcpy(_c, at, length);
    _c[length] = '\0';

    var = php_strtok_r(_c, separator, &strtok_buf);
    while (var) {
        var_len = swoole::ltrim(&var, strlen(var));
        var_len = swoole::rtrim(var, var_len);
        if (swoole_strcaseeq(var, var_len, value, strlen(value))) {
            return true;
        }
        var = php_strtok_r(nullptr, separator, &strtok_buf);
    }
    return false;
}

static int http_request_on_header_value(swoole_http_parser *parser, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) parser->data;
    zval *zheader = ctx->request.zheader;
    size_t header_len = ctx->current_header_name_len;
    char *header_name = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (ctx->parse_cookie && SW_STREQ(header_name, header_len, "cookie")) {
        zval *zcookie = swoole_http_init_and_read_property(
            swoole_http_request_ce, ctx->request.zobject, &ctx->request.zcookie, ZEND_STRL("cookie"));
        swoole_http_parse_cookie(zcookie, at, length);
        efree(header_name);
        return 0;
    } else if (SW_STREQ(header_name, header_len, "upgrade") && swoole_http_token_list_contains_value(at, length, "websocket")) {
        ctx->websocket = 1;
        if (ctx->co_socket) {
            goto _add_header;
        }
        Server *serv = (Server *) ctx->private_data;
        if (!serv) {
            goto _add_header;
        }
        Connection *conn = serv->get_connection_by_session_id(ctx->fd);
        if (!conn) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSED, "session[%ld] is closed", ctx->fd);
            efree(header_name);
            return -1;
        }
        ListenPort *port = serv->get_port_by_server_fd(conn->server_fd);
        if (port->open_websocket_protocol) {
            conn->websocket_status = swoole::websocket::STATUS_CONNECTION;
        }
    } else if ((parser->method == PHP_HTTP_POST || parser->method == PHP_HTTP_PUT ||
                parser->method == PHP_HTTP_DELETE || parser->method == PHP_HTTP_PATCH) &&
               SW_STREQ(header_name, header_len, "content-type")) {
        if (SW_STRCASECT(at, length, "application/x-www-form-urlencoded")) {
            ctx->request.post_form_urlencoded = 1;
        } else if (SW_STRCASECT(at, length, "multipart/form-data")) {
            size_t offset = sizeof("multipart/form-data") - 1;
            char *boundary_str;
            int boundary_len;
            if (!ctx->get_form_data_boundary(at, length, offset, &boundary_str, &boundary_len)) {
                return -1;
            }
            swoole_trace_log(SW_TRACE_HTTP, "form_data, boundary_str=%s", boundary_str);
            ctx->init_multipart_parser(boundary_str, boundary_len);
        }
    }
#ifdef SW_HAVE_COMPRESSION
    else if (ctx->enable_compression && SW_STREQ(header_name, header_len, "accept-encoding")) {
        ctx->set_compression_method(at, length);
    }
#endif
    else if (SW_STREQ(header_name, header_len, "transfer-encoding") && SW_STRCASECT(at, length, "chunked")) {
        ctx->recv_chunked = 1;
    }

_add_header:
    add_assoc_stringl_ex(zheader, header_name, header_len, (char *) at, length);
    efree(header_name);

    return 0;
}

static int http_request_on_headers_complete(swoole_http_parser *parser) {
    HttpContext *ctx = (HttpContext *) parser->data;
    const char *vpath = ctx->request.path, *end = vpath + ctx->request.path_len, *p = end;
    zval *zserver = ctx->request.zserver;

    ctx->request.version = parser->http_major * 100 + parser->http_minor;
    ctx->request.ext = end;
    ctx->request.ext_len = 0;

    while (p > vpath) {
        --p;
        if (*p == '.') {
            ++p;
            ctx->request.ext = p;
            ctx->request.ext_len = end - p;
            break;
        }
    }

    ctx->keepalive = swoole_http_should_keep_alive(parser);

    add_assoc_string(zserver, "request_method", http_get_method_name(parser->method));
    add_assoc_stringl_ex(zserver, ZEND_STRL("request_uri"), ctx->request.path, ctx->request.path_len);
    // path_info should be decoded
    zend_string *zstr_path = zend_string_init(ctx->request.path, ctx->request.path_len, 0);
    ZSTR_LEN(zstr_path) = php_url_decode(ZSTR_VAL(zstr_path), ZSTR_LEN(zstr_path));
    add_assoc_str_ex(zserver, ZEND_STRL("path_info"), zstr_path);
    add_assoc_long_ex(zserver, ZEND_STRL("request_time"), time(nullptr));
    add_assoc_double_ex(zserver, ZEND_STRL("request_time_float"), microtime());
    add_assoc_string(zserver, "server_protocol", (char *) (ctx->request.version == 101 ? "HTTP/1.1" : "HTTP/1.0"));

    ctx->current_header_name = nullptr;

    return 0;
}

static int multipart_body_on_header_field(multipart_parser *p, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) p->data;
    return http_request_on_header_field(&ctx->parser, at, length);
}

static int multipart_body_on_header_value(multipart_parser *p, const char *at, size_t length) {
    char value_buf[SW_HTTP_FORM_KEYLEN];
    size_t value_len;
    int ret = 0;

    HttpContext *ctx = (HttpContext *) p->data;
    /**
     * Hash collision attack
     */
    if (ctx->input_var_num > PG(max_input_vars)) {
        php_swoole_error(E_WARNING,
                         "Input variables exceeded " ZEND_LONG_FMT ". "
                         "To increase the limit change max_input_vars in php.ini",
                         PG(max_input_vars));
        return SW_OK;
    } else {
        ctx->input_var_num++;
    }

    size_t header_len = ctx->current_header_name_len;
    char *header_name = zend_str_tolower_dup(ctx->current_header_name, header_len);

    if (SW_STRCASEEQ(header_name, header_len, "content-disposition")) {
        size_t offset = 0;
        if (swoole_strnpos(at, length, ZEND_STRL("form-data;")) >= 0) {
            offset += sizeof("form-data;") - 1;
        } else if (swoole_strnpos(at, length, ZEND_STRL("attachment;")) >= 0) {
            offset += sizeof("attachment;") - 1;
        } else {
            swoole_warning("Unsupported Content-Disposition [%.*s]", (int) length, at);
            goto _end;
        }

        zval tmp_array;
        array_init(&tmp_array);
        swoole_http_parse_cookie(&tmp_array, at + offset, length - offset);

        zval *zform_name;
        if (!(zform_name = zend_hash_str_find(Z_ARRVAL(tmp_array), ZEND_STRL("name")))) {
            goto _end;
        }

        if (Z_STRLEN_P(zform_name) >= SW_HTTP_FORM_KEYLEN) {
            swoole_warning("form_name[%s] is too large", Z_STRVAL_P(zform_name));
            ret = -1;
            goto _end;
        }

        swoole_strlcpy(value_buf, Z_STRVAL_P(zform_name), sizeof(value_buf));
        value_len = Z_STRLEN_P(zform_name);
        char *tmp = http_trim_double_quote(value_buf, &value_len);

        zval *zfilename;
        // POST form data
        if (!(zfilename = zend_hash_str_find(Z_ARRVAL(tmp_array), ZEND_STRL("filename")))) {
            ctx->current_form_data_name = estrndup(tmp, value_len);
            ctx->current_form_data_name_len = value_len;
        }
        // upload file
        else {
            if (Z_STRLEN_P(zfilename) >= SW_HTTP_FORM_KEYLEN) {
                swoole_warning("filename[%s] is too large", Z_STRVAL_P(zfilename));
                ret = -1;
                goto _end;
            }
            ctx->current_input_name = estrndup(tmp, value_len);
            ctx->current_input_name_len = value_len;

            zval *z_multipart_header = sw_malloc_zval();
            array_init(z_multipart_header);

            swoole_strlcpy(value_buf, Z_STRVAL_P(zfilename), sizeof(value_buf));
            value_len = Z_STRLEN_P(zfilename);
            tmp = http_trim_double_quote(value_buf, &value_len);

            add_assoc_stringl(z_multipart_header, "name", tmp, value_len);
            add_assoc_string(z_multipart_header, "type", (char *) "");
            add_assoc_string(z_multipart_header, "tmp_name", (char *) "");

            if (value_len == 0) {
                add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_NO_FILE);
            } else {
                add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_OK);
            }

            add_assoc_long(z_multipart_header, "size", 0);

            ctx->current_multipart_header = z_multipart_header;
        }
        zval_ptr_dtor(&tmp_array);
    } else if (SW_STRCASEEQ(header_name, header_len, "content-type") && ctx->current_multipart_header) {
        zval *z_multipart_header = ctx->current_multipart_header;
        zval *zerr = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("error"));
        if (zerr && Z_TYPE_P(zerr) == IS_LONG && Z_LVAL_P(zerr) == HTTP_UPLOAD_ERR_OK) {
            add_assoc_stringl(z_multipart_header, "type", (char *) at, length);
        }
    }

_end:
    efree(header_name);

    return ret;
}

static int multipart_body_on_data(multipart_parser *p, const char *at, size_t length) {
    HttpContext *ctx = (HttpContext *) p->data;
    if (ctx->current_form_data_name) {
        ctx->form_data_buffer->append(at, length);
        return 0;
    }
    if (p->fp == nullptr) {
        return 0;
    }
    ssize_t n = fwrite(at, sizeof(char), length, p->fp);
    if (n != (off_t) length) {
        zval *z_multipart_header = ctx->current_multipart_header;
        add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_CANT_WRITE);

        fclose(p->fp);
        p->fp = nullptr;

        swoole_sys_warning("write upload file failed");
    }
    return 0;
}

#if 0
static void get_random_file_name(char *des, const char *src)
{
    unsigned char digest[16] = {};
    char buf[19] = {};
    int n = sprintf(buf, "%s%d", src, swoole_system_random(0, 9999));

    PHP_MD5_CTX ctx;
    PHP_MD5Init(&ctx);
    PHP_MD5Update(&ctx, buf, n);
    PHP_MD5Final(digest, &ctx);
    make_digest_ex(des, digest, 16);
}
#endif

static int multipart_body_on_header_complete(multipart_parser *p) {
    HttpContext *ctx = (HttpContext *) p->data;
    if (!ctx->current_input_name) {
        return 0;
    }

    zval *z_multipart_header = ctx->current_multipart_header;
    zval *zerr = nullptr;
    if (!(zerr = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("error")))) {
        return 0;
    }
    if (Z_TYPE_P(zerr) == IS_LONG && Z_LVAL_P(zerr) != HTTP_UPLOAD_ERR_OK) {
        return 0;
    }

    char file_path[SW_HTTP_UPLOAD_TMPDIR_SIZE];
    sw_snprintf(file_path, SW_HTTP_UPLOAD_TMPDIR_SIZE, "%s/swoole.upfile.XXXXXX", ctx->upload_tmp_dir.c_str());
    int tmpfile = swoole_tmpfile(file_path);
    if (tmpfile < 0) {
        return 0;
    }

    FILE *fp = fdopen(tmpfile, "wb+");
    if (fp == nullptr) {
        add_assoc_long(z_multipart_header, "error", HTTP_UPLOAD_ERR_NO_TMP_DIR);
        swoole_sys_warning("fopen(%s) failed", file_path);
        return 0;
    }

    p->fp = fp;
    add_assoc_string(z_multipart_header, "tmp_name", file_path);

    size_t file_path_len = strlen(file_path);
    add_next_index_stringl(
        swoole_http_init_and_read_property(
            swoole_http_request_ce, ctx->request.zobject, &ctx->request.ztmpfiles, ZEND_STRL("tmpfiles")),
        file_path,
        file_path_len);
    // support is_upload_file
    zend_hash_str_add_ptr(SG(rfc1867_uploaded_files), file_path, file_path_len, (char *) file_path);

    return 0;
}

static int multipart_body_on_data_end(multipart_parser *p) {
    HttpContext *ctx = (HttpContext *) p->data;

    if (ctx->current_form_data_name) {
        php_register_variable_safe(
            ctx->current_form_data_name,
            ctx->form_data_buffer->str,
            ctx->form_data_buffer->length,
            swoole_http_init_and_read_property(
                swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post")));

        efree(ctx->current_form_data_name);
        ctx->current_form_data_name = nullptr;
        ctx->current_form_data_name_len = 0;
        ctx->form_data_buffer->clear();
        return 0;
    }

    if (!ctx->current_input_name) {
        return 0;
    }

    zval *z_multipart_header = ctx->current_multipart_header;
    if (p->fp != nullptr) {
        long size = swoole::file_get_size(p->fp);
        add_assoc_long(z_multipart_header, "size", size);

        fclose(p->fp);
        p->fp = nullptr;
    }

    zval *zfiles = swoole_http_init_and_read_property(
        swoole_http_request_ce, ctx->request.zobject, &ctx->request.zfiles, ZEND_STRL("files"));

    int input_path_pos = swoole_strnpos(ctx->current_input_name, ctx->current_input_name_len, ZEND_STRL("["));
    if (ctx->parse_files && input_path_pos > 0) {
        char meta_name[SW_HTTP_FORM_KEYLEN + sizeof("[tmp_name]") - 1];
        char *input_path = ctx->current_input_name + input_path_pos;
        char *meta_path = meta_name + input_path_pos;
        size_t meta_path_len = sizeof(meta_name) - input_path_pos;

        swoole_strlcpy(meta_name, ctx->current_input_name, sizeof(meta_name));

        zval *zname = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("name"));
        zval *ztype = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("type"));
        zval *zfile = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("tmp_name"));
        zval *zerr = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("error"));
        zval *zsize = zend_hash_str_find(Z_ARRVAL_P(z_multipart_header), ZEND_STRL("size"));

        sw_snprintf(meta_path, meta_path_len, "[name]%s", input_path);
        php_register_variable_ex(meta_name, zname, zfiles);

        sw_snprintf(meta_path, meta_path_len, "[type]%s", input_path);
        php_register_variable_ex(meta_name, ztype, zfiles);

        sw_snprintf(meta_path, meta_path_len, "[tmp_name]%s", input_path);
        php_register_variable_ex(meta_name, zfile, zfiles);

        sw_snprintf(meta_path, meta_path_len, "[error]%s", input_path);
        php_register_variable_ex(meta_name, zerr, zfiles);

        sw_snprintf(meta_path, meta_path_len, "[size]%s", input_path);
        php_register_variable_ex(meta_name, zsize, zfiles);
    } else {
        php_register_variable_ex(ctx->current_input_name, z_multipart_header, zfiles);
    }

    efree(ctx->current_input_name);
    ctx->current_input_name = nullptr;
    ctx->current_input_name_len = 0;
    efree(ctx->current_multipart_header);
    ctx->current_multipart_header = nullptr;

    return 0;
}

static int http_request_on_body(swoole_http_parser *parser, const char *at, size_t length) {
    if (length == 0) {
        return 0;
    }

    HttpContext *ctx = (HttpContext *) parser->data;
    bool is_beginning = (ctx->request.chunked_body ? ctx->request.chunked_body->length : ctx->request.body_length) == 0;

    if (ctx->recv_chunked) {
        if (ctx->request.chunked_body == nullptr) {
            ctx->request.chunked_body = new swoole::String(SW_BUFFER_SIZE_STD);
        }
        ctx->request.chunked_body->append(at, length);
    } else {
        ctx->request.body_at = at - ctx->request.body_length;
        ctx->request.body_length += length;
    }

    if (ctx->mt_parser != nullptr) {
        if (is_beginning) {
            /* Compatibility: some clients may send extra EOL */
            do {
                if (*at != '\r' && *at != '\n') {
                    break;
                }
                at++;
                length--;
            } while (length != 0);
        }
        ctx->parse_multipart_data(at, length);
    }

    return 0;
}

static int http_request_message_complete(swoole_http_parser *parser) {
    HttpContext *ctx = (HttpContext *) parser->data;
    size_t content_length = ctx->request.chunked_body ? ctx->request.chunked_body->length : ctx->request.body_length;

    if (ctx->request.chunked_body != nullptr && ctx->parse_body && ctx->request.post_form_urlencoded) {
        /* parse dechunked content */
        sapi_module.treat_data(
            PARSE_STRING,
            estrndup(ctx->request.chunked_body->str, content_length),  // do not free, it will be freed by treat_data
            swoole_http_init_and_read_property(
                swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post")));
    } else if (!ctx->recv_chunked && ctx->parse_body && ctx->request.post_form_urlencoded && ctx->request.body_at) {
        sapi_module.treat_data(
            PARSE_STRING,
            estrndup(ctx->request.body_at, ctx->request.body_length),  // do not free, it will be freed by treat_data
            swoole_http_init_and_read_property(
                swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post")));
    }
    if (ctx->mt_parser) {
        multipart_parser_free(ctx->mt_parser);
        ctx->mt_parser = nullptr;
    }
    if (ctx->form_data_buffer) {
        delete ctx->form_data_buffer;
        ctx->form_data_buffer = nullptr;
    }

    ctx->completed = 1;

    swoole_trace_log(SW_TRACE_HTTP, "request body length=%ld", content_length);

    return 1; /* return from execute */
}

#ifdef SW_HAVE_COMPRESSION
void HttpContext::set_compression_method(const char *accept_encoding, size_t length) {
#ifdef SW_HAVE_BROTLI
    if (swoole_strnpos(accept_encoding, length, ZEND_STRL("br")) >= 0) {
        accept_compression = 1;
        compression_method = HTTP_COMPRESS_BR;
    } else
#endif
        if (swoole_strnpos(accept_encoding, length, ZEND_STRL("gzip")) >= 0) {
        accept_compression = 1;
        compression_method = HTTP_COMPRESS_GZIP;
    } else if (swoole_strnpos(accept_encoding, length, ZEND_STRL("deflate")) >= 0) {
        accept_compression = 1;
        compression_method = HTTP_COMPRESS_DEFLATE;
    } else {
        accept_compression = 0;
    }
}

const char *HttpContext::get_content_encoding() {
    if (compression_method == HTTP_COMPRESS_GZIP) {
        return "gzip";
    } else if (compression_method == HTTP_COMPRESS_DEFLATE) {
        return "deflate";
    }
#ifdef SW_HAVE_BROTLI
    else if (compression_method == HTTP_COMPRESS_BR) {
        return "br";
    }
#endif
    else {
        return nullptr;
    }
}
#endif

static PHP_METHOD(swoole_http_request, getContent) {
    HttpContext *ctx = php_swoole_http_request_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    HttpRequest *req = &ctx->request;
    if (req->body_length > 0) {
        zval *zdata = &req->zdata;
        RETURN_STRINGL(Z_STRVAL_P(zdata) + Z_STRLEN_P(zdata) - req->body_length, req->body_length);
    } else if (req->chunked_body && req->chunked_body->length != 0) {
        RETURN_STRINGL(req->chunked_body->str, req->chunked_body->length);
    }
#ifdef SW_USE_HTTP2
    else if (req->h2_data_buffer && req->h2_data_buffer->length != 0) {
        RETURN_STRINGL(req->h2_data_buffer->str, req->h2_data_buffer->length);
    }
#endif

    RETURN_EMPTY_STRING();
}

static PHP_METHOD(swoole_http_request, getData) {
    HttpContext *ctx = php_swoole_http_request_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->http2) {
        php_swoole_fatal_error(E_WARNING, "unable to get data from HTTP2 request");
        RETURN_FALSE;
    }
#endif

    if (Z_TYPE(ctx->request.zdata) == IS_STRING) {
        RETURN_ZVAL(&ctx->request.zdata, 1, 0);
    }

    RETURN_EMPTY_STRING();
}

static PHP_METHOD(swoole_http_request, create) {
    zval *zoptions = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(zoptions)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (sw_unlikely(swoole_http_buffer == nullptr)) {
        php_swoole_http_server_init_global_variant();
    }

    HttpContext *ctx = new HttpContext();
    object_init_ex(return_value, swoole_http_request_ce);
    zval *zrequest_object = &ctx->request._zobject;
    ctx->request.zobject = zrequest_object;
    *zrequest_object = *return_value;
    php_swoole_http_request_set_context(zrequest_object, ctx);

    ctx->parse_cookie = 1;
    ctx->parse_body = 1;
    ctx->parse_files = 1;
#ifdef SW_HAVE_COMPRESSION
    ctx->enable_compression = 1;
    ctx->compression_level = SW_Z_BEST_SPEED;
#endif
    ctx->upload_tmp_dir = "/tmp";

    if (zoptions && ZVAL_IS_ARRAY(zoptions)) {
        char *key;
        uint32_t keylen;
        int keytype;
        zval *zvalue;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zoptions), key, keylen, keytype, zvalue) {
            if (SW_STRCASEEQ(key, keylen, "parse_cookie")) {
                ctx->parse_cookie = zval_is_true(zvalue);
            } else if (SW_STRCASEEQ(key, keylen, "parse_body")) {
                ctx->parse_body = zval_is_true(zvalue);
            } else if (SW_STRCASEEQ(key, keylen, "parse_files")) {
                ctx->parse_files = zval_is_true(zvalue);
            }
#ifdef SW_HAVE_COMPRESSION
            else if (SW_STRCASEEQ(key, keylen, "enable_compression")) {
                ctx->enable_compression = zval_is_true(zvalue);
            } else if (SW_STRCASEEQ(key, keylen, "compression_level")) {
                ctx->compression_level = zval_get_long(zvalue);
            }
#endif
#ifdef SW_HAVE_ZLIB
            else if (SW_STRCASEEQ(key, keylen, "websocket_compression")) {
                ctx->websocket_compression = zval_is_true(zvalue);
            }
#endif
            else if (SW_STRCASEEQ(key, keylen, "upload_tmp_dir")) {
                ctx->upload_tmp_dir = zend::String(zvalue).to_std_string();
            }
            (void) keytype;
        }
        SW_HASHTABLE_FOREACH_END();
    }

    swoole_http_parser *parser = &ctx->parser;
    parser->data = ctx;
    swoole_http_parser_init(parser, PHP_HTTP_REQUEST);

    swoole_http_init_and_read_property(
        swoole_http_request_ce, zrequest_object, &ctx->request.zserver, ZEND_STRL("server"));
    swoole_http_init_and_read_property(
        swoole_http_request_ce, zrequest_object, &ctx->request.zheader, ZEND_STRL("header"));
}

static PHP_METHOD(swoole_http_request, parse) {
    HttpContext *ctx = php_swoole_http_request_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx) || ctx->completed) {
        RETURN_FALSE;
    }

    char *str;
    size_t l_str;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(str, l_str)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (Z_TYPE(ctx->request.zdata) != IS_STRING) {
        ZVAL_STRINGL(&ctx->request.zdata, str, l_str);
    } else {
        size_t len = Z_STRLEN(ctx->request.zdata) + l_str;
        zend_string *new_str = zend_string_alloc(len + 1, 0);
        memcpy(new_str->val, Z_STRVAL(ctx->request.zdata), Z_STRLEN(ctx->request.zdata));
        memcpy(new_str->val + Z_STRLEN(ctx->request.zdata), str, l_str);
        new_str->val[len] = 0;
        new_str->len = len;
        zval_dtor(&ctx->request.zdata);
        ZVAL_STR(&ctx->request.zdata, new_str);
    }

    RETURN_LONG(ctx->parse(str, l_str));
}

static PHP_METHOD(swoole_http_request, getMethod) {
    HttpContext *ctx = php_swoole_http_request_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    const char *method = http_get_method_name((ctx->parser).method);
    RETURN_STRING(method);
}

static PHP_METHOD(swoole_http_request, isCompleted) {
    HttpContext *ctx = php_swoole_http_request_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    RETURN_BOOL(ctx->completed);
}

static PHP_METHOD(swoole_http_request, __destruct) {}
