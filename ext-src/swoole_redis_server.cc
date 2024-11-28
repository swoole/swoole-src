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

#include "php_swoole_server.h"
#include "swoole_redis.h"

#include <unordered_map>
#include <string>

BEGIN_EXTERN_C()
#include "ext/standard/php_string.h"
#include "stubs/php_swoole_redis_server_arginfo.h"
END_EXTERN_C()

using swoole::Connection;
using swoole::ListenPort;
using swoole::RecvData;
using swoole::Server;
using swoole::String;

namespace Redis = swoole::redis;

zend_class_entry *swoole_redis_server_ce;
zend_object_handlers swoole_redis_server_handlers;

static SW_THREAD_LOCAL std::unordered_map<std::string, zend::Callable *> redis_handlers;

static bool redis_response_format(String *buf, zend_long type, zval *value);

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_redis_server, setHandler);
static PHP_METHOD(swoole_redis_server, getHandler);
static PHP_METHOD(swoole_redis_server, format);
SW_EXTERN_C_END

// clang-format off
const zend_function_entry swoole_redis_server_methods[] =
{
    PHP_ME(swoole_redis_server, setHandler, arginfo_class_Swoole_Redis_Server_setHandler, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, getHandler, arginfo_class_Swoole_Redis_Server_getHandler, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, format,     arginfo_class_Swoole_Redis_Server_format,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_redis_server_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_EX(
        swoole_redis_server, "Swoole\\Redis\\Server", nullptr, swoole_redis_server_methods, swoole_server);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_redis_server);
    SW_SET_CLASS_CLONEABLE(swoole_redis_server, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_redis_server, sw_zend_class_unset_property_deny);

    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("NIL"), Redis::REPLY_NIL);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("ERROR"), Redis::REPLY_ERROR);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("STATUS"), Redis::REPLY_STATUS);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("INT"), Redis::REPLY_INT);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("STRING"), Redis::REPLY_STRING);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("SET"), Redis::REPLY_SET);
    zend_declare_class_constant_long(swoole_redis_server_ce, ZEND_STRL("MAP"), Redis::REPLY_MAP);
}

void php_swoole_redis_server_rshutdown() {
    for (auto i = redis_handlers.begin(); i != redis_handlers.end(); i++) {
        sw_callable_free(i->second);
    }
    redis_handlers.clear();
}

int php_swoole_redis_server_onReceive(Server *serv, RecvData *req) {
    int fd = req->info.fd;
    Connection *conn = serv->get_connection_by_session_id(fd);
    if (!conn) {
        swoole_warning("connection[%d] is closed", fd);
        return SW_ERR;
    }

    ListenPort *port = serv->get_port_by_fd(conn->fd);
    // other server port
    if (!port->open_redis_protocol) {
        return php_swoole_server_onReceive(serv, req);
    }

    zval zdata;
    php_swoole_get_recv_data(serv, &zdata, req);
    const char *p = Z_STRVAL(zdata);
    const char *pe = p + Z_STRLEN(zdata);
    int ret;
    int length = 0;

    zval zparams{};
    array_init(&zparams);

    int state = Redis::STATE_RECEIVE_TOTAL_LINE;
    int add_param = 0;
    const char *command = nullptr;
    int command_len = 0;

    do {
        switch (state) {
        case Redis::STATE_RECEIVE_TOTAL_LINE:
            if (*p == '*' && (p = Redis::get_number(p, &ret))) {
                state = Redis::STATE_RECEIVE_LENGTH;
                break;
            }
            /* no break */

        case Redis::STATE_RECEIVE_LENGTH:
            if (*p == '$' && (p = Redis::get_number(p, &ret))) {
                if (ret == -1) {
                    add_next_index_null(&zparams);
                    break;
                }
                length = ret;
                state = Redis::STATE_RECEIVE_STRING;
                break;
            }
            // integer
            else if (*p == ':' && (p = Redis::get_number(p, &ret))) {
                add_next_index_long(&zparams, ret);
                break;
            }
            /* no break */

        case Redis::STATE_RECEIVE_STRING:
            if (add_param == 0) {
                command = p;
                command_len = length;
                add_param = 1;
            } else {
                add_next_index_stringl(&zparams, p, length);
            }
            p += length + SW_CRLF_LEN;
            state = Redis::STATE_RECEIVE_LENGTH;
            break;

        default:
            break;
        }
    } while (p < pe);

    if (command_len >= SW_REDIS_MAX_COMMAND_SIZE) {
        php_swoole_error(E_WARNING, "command [%.8s...](length=%d) is too long", command, command_len);
        serv->close(fd, false);
        return SW_OK;
    }

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    size_t _command_len = sw_snprintf(_command, sizeof(_command), "_handler_%.*s", command_len, command);
#if PHP_VERSION_ID >= 80400
    zend_str_tolower(_command, _command_len);
#else
    php_strtolower(_command, _command_len);
#endif

    auto i = redis_handlers.find(std::string(_command, _command_len));
    if (i == redis_handlers.end()) {
        char err_msg[256];
        length = sw_snprintf(err_msg, sizeof(err_msg), "-ERR unknown command '%.*s'\r\n", command_len, command);
        return serv->send(fd, err_msg, length) ? SW_OK : SW_ERR;
    }

    auto fci_cache = i->second;
    zval args[2];
    zval retval;

    ZVAL_LONG(&args[0], fd);
    args[1] = zparams;

    if (UNEXPECTED(!zend::function::call(fci_cache->ptr(), 2, args, &retval, serv->is_enable_coroutine()))) {
        php_swoole_error(E_WARNING,
                         "%s->onRequest with command '%.*s' handler error",
                         ZSTR_VAL(swoole_redis_server_ce->name),
                         command_len,
                         command);
    }

    if (Z_TYPE_P(&retval) == IS_STRING) {
        serv->send(fd, Z_STRVAL_P(&retval), Z_STRLEN_P(&retval));
    }
    zval_ptr_dtor(&retval);
    zval_ptr_dtor(&zdata);
    zval_ptr_dtor(&zparams);

    return SW_OK;
}

static PHP_METHOD(swoole_redis_server, setHandler) {
    char *command;
    size_t command_len;
    zval *zcallback;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(command, command_len)
    Z_PARAM_ZVAL(zcallback)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (command_len == 0 || command_len >= SW_REDIS_MAX_COMMAND_SIZE) {
        php_swoole_fatal_error(E_ERROR, "invalid command");
        RETURN_FALSE;
    }

    auto fci_cache = sw_callable_create(zcallback);
    if (!fci_cache) {
        return;
    }

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    size_t _command_len = sw_snprintf(_command, sizeof(_command), "_handler_%s", command);
#if PHP_VERSION_ID >= 80400
    zend_str_tolower(_command, _command_len);
#else
    php_strtolower(_command, _command_len);
#endif

    zend_update_property(swoole_redis_server_ce, SW_Z8_OBJ_P(ZEND_THIS), _command, _command_len, zcallback);

    std::string key(_command, _command_len);
    auto i = redis_handlers.find(key);
    if (i != redis_handlers.end()) {
        sw_callable_free(i->second);
    }

    redis_handlers[key] = fci_cache;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_server, getHandler) {
    char *command;
    size_t command_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(command, command_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    size_t _command_len = sw_snprintf(_command, sizeof(_command), "_handler_%s", command);
#if PHP_VERSION_ID >= 80400
    zend_str_tolower(_command, _command_len);
#else
    php_strtolower(_command, _command_len);
#endif

    zval rv;
    zval *handler = zend_read_property(swoole_redis_server_ce, SW_Z8_OBJ_P(ZEND_THIS), _command, _command_len, 1, &rv);
    RETURN_ZVAL(handler, 1, 0);
}

static void redis_response_format_array_item(String *buf, zval *item) {
    switch (Z_TYPE_P(item)) {
    case IS_LONG:
    case IS_FALSE:
    case IS_TRUE:
        redis_response_format(buf, Redis::REPLY_INT, item);
        break;
    case IS_ARRAY:
        if (zend_array_is_list(Z_ARRVAL_P(item))) {
            redis_response_format(buf, Redis::REPLY_SET, item);
        } else {
            redis_response_format(buf, Redis::REPLY_MAP, item);
        }
        break;
    default:
        redis_response_format(buf, Redis::REPLY_STRING, item);
        break;
    }
}

static bool redis_response_format(String *buf, zend_long type, zval *value) {
    if (type == Redis::REPLY_NIL) {
        buf->append(SW_STRL(SW_REDIS_RETURN_NIL));
    } else if (type == Redis::REPLY_ERROR || type == Redis::REPLY_STATUS) {
        char flag = type == Redis::REPLY_ERROR ? '-' : '+';
        const char *default_message = type == Redis::REPLY_ERROR ? "ERR" : "OK";
        if (value) {
            zend::String str_value(value);
            SW_STRING_FORMAT(buf, "%c%.*s\r\n", flag, (int) str_value.len(), str_value.val());
        } else {
            SW_STRING_FORMAT(buf, "%c%s\r\n", flag, default_message);
        }
    } else if (type == Redis::REPLY_INT) {
        if (!value) {
            goto _no_value;
        }
        SW_STRING_FORMAT(buf, ":" ZEND_LONG_FMT "\r\n", zval_get_long(value));
    } else if (type == Redis::REPLY_STRING) {
        if (!value) {
        _no_value:
            php_swoole_fatal_error(E_WARNING, "require more parameters");
            return false;
        }
        zend::String str_value(value);
        if (str_value.len() > SW_REDIS_MAX_STRING_SIZE || str_value.len() < 1) {
            php_swoole_fatal_error(E_WARNING, "invalid string size");
            return false;
        }
        SW_STRING_FORMAT(buf, "$%zu\r\n", str_value.len());
        buf->append(str_value.val(), str_value.len());
        buf->append(SW_CRLF, SW_CRLF_LEN);
    } else if (type == Redis::REPLY_SET) {
        if (!value) {
            goto _no_value;
        }
        if (!ZVAL_IS_ARRAY(value)) {
            php_swoole_fatal_error(E_WARNING, "the second parameter should be an array");
        }
        SW_STRING_FORMAT(buf, "*%d\r\n", zend_hash_num_elements(Z_ARRVAL_P(value)));

        zval *item;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(value), item) {
            redis_response_format_array_item(buf, item);
        }
        ZEND_HASH_FOREACH_END();
    } else if (type == Redis::REPLY_MAP) {
        if (!value) {
            goto _no_value;
        }
        if (!ZVAL_IS_ARRAY(value)) {
            php_swoole_fatal_error(E_WARNING, "the second parameter should be an array");
        }
        SW_STRING_FORMAT(buf, "*%d\r\n", 2 * zend_hash_num_elements(Z_ARRVAL_P(value)));

        zend_string *key;
        zend_ulong num_key;
        zval *item;
        ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(value), num_key, key, item) {
            if (key) {
                SW_STRING_FORMAT(buf, "$%zu\r\n%.*s\r\n", ZSTR_LEN(key), (int) ZSTR_LEN(key), ZSTR_VAL(key));
            } else {
                std::string _key = std::to_string(num_key);
                SW_STRING_FORMAT(buf, "$%zu\r\n%.*s\r\n", _key.length(), (int) _key.length(), _key.c_str());
            }
            redis_response_format_array_item(buf, item);
        }
        ZEND_HASH_FOREACH_END();
    } else {
        php_swoole_error(E_WARNING, "Unknown type[%d]", (int) type);
        return false;
    }

    return true;
}

static PHP_METHOD(swoole_redis_server, format) {
    zend_long type;
    zval *value = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(type)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(value)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    auto buf = std::shared_ptr<String>(swoole::make_string(1024, sw_zend_string_allocator()));
    if (!redis_response_format(buf.get(), type, value)) {
        RETURN_FALSE;
    }

    auto str = zend::fetch_zend_string_by_val(buf->str);
    buf->set_null_terminated();
    str->len = buf->length;
    buf->release();
    RETURN_STR(str);
}
