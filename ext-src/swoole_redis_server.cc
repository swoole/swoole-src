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
END_EXTERN_C()

using swoole::Server;
using swoole::RecvData;
using swoole::ListenPort;
using swoole::Connection;

namespace Redis = swoole::redis;

zend_class_entry *swoole_redis_server_ce;
zend_object_handlers swoole_redis_server_handlers;

static std::unordered_map<std::string, zend_fcall_info_cache> redis_handlers;

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_redis_server, setHandler);
static PHP_METHOD(swoole_redis_server, getHandler);
static PHP_METHOD(swoole_redis_server, format);
SW_EXTERN_C_END

// clang-format off
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_setHandler, 0, 0, 2)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_getHandler, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_format, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_redis_server_methods[] =
{
    PHP_ME(swoole_redis_server, setHandler, arginfo_swoole_redis_server_setHandler, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, getHandler, arginfo_swoole_redis_server_getHandler, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, format, arginfo_swoole_redis_server_format, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_redis_server_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_EX(swoole_redis_server,
                           "Swoole\\Redis\\Server",
                           "swoole_redis_server",
                           nullptr,
                           swoole_redis_server_methods,
                           swoole_server);
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
        sw_zend_fci_cache_discard(&i->second);
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
    php_strtolower(_command, _command_len);

    auto i = redis_handlers.find(std::string(_command, _command_len));
    if (i == redis_handlers.end()) {
        char err_msg[256];
        length = sw_snprintf(err_msg, sizeof(err_msg), "-ERR unknown command '%.*s'\r\n", command_len, command);
        return serv->send(fd, err_msg, length) ? SW_OK : SW_ERR;
    }

    zend_fcall_info_cache *fci_cache = &i->second;
    zval args[2];
    zval retval;

    ZVAL_LONG(&args[0], fd);
    args[1] = zparams;

    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, &retval, serv->is_enable_coroutine()))) {
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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &command, &command_len, &zcallback) == FAILURE) {
        RETURN_FALSE;
    }

    if (command_len == 0 || command_len >= SW_REDIS_MAX_COMMAND_SIZE) {
        php_swoole_fatal_error(E_ERROR, "invalid command");
        RETURN_FALSE;
    }

    char *func_name;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(zcallback, nullptr, 0, &func_name, nullptr, fci_cache, nullptr)) {
        php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    size_t _command_len = sw_snprintf(_command, sizeof(_command), "_handler_%s", command);
    php_strtolower(_command, _command_len);

    zend_update_property(swoole_redis_server_ce, SW_Z8_OBJ_P(ZEND_THIS), _command, _command_len, zcallback);

    std::string key(_command, _command_len);
    auto i = redis_handlers.find(key);
    if (i != redis_handlers.end()) {
        sw_zend_fci_cache_discard(&i->second);
    }

    sw_zend_fci_cache_persist(fci_cache);
    redis_handlers[key] = *fci_cache;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_server, getHandler) {
    char *command;
    size_t command_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &command, &command_len) == FAILURE) {
        RETURN_FALSE;
    }

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    size_t _command_len = sw_snprintf(_command, sizeof(_command), "_handler_%s", command);
    php_strtolower(_command, _command_len);

    zval rv;
    zval *handler = zend_read_property(swoole_redis_server_ce, SW_Z8_OBJ_P(ZEND_THIS), _command, _command_len, 1, &rv);
    RETURN_ZVAL(handler, 1, 0);
}

static PHP_METHOD(swoole_redis_server, format) {
    zend_long type;
    zval *value = nullptr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|z", &type, &value) == FAILURE) {
        RETURN_FALSE;
    }

    char message[256];
    int length;

    swoole::String *format_buffer = sw_tg_buffer();

    if (type == Redis::REPLY_NIL) {
        RETURN_STRINGL(SW_REDIS_RETURN_NIL, sizeof(SW_REDIS_RETURN_NIL) - 1);
    } else if (type == Redis::REPLY_STATUS) {
        if (value) {
            zend::String str_value(value);
            length = sw_snprintf(message, sizeof(message), "+%.*s\r\n", (int) str_value.len(), str_value.val());
        } else {
            length = sw_snprintf(message, sizeof(message), "+%s\r\n", "OK");
        }
        RETURN_STRINGL(message, length);
    } else if (type == Redis::REPLY_ERROR) {
        if (value) {
            zend::String str_value(value);
            length = sw_snprintf(message, sizeof(message), "-%.*s\r\n", (int) str_value.len(), str_value.val());
        } else {
            length = sw_snprintf(message, sizeof(message), "-%s\r\n", "ERR");
        }
        RETURN_STRINGL(message, length);
    } else if (type == Redis::REPLY_INT) {
        if (!value) {
            goto _no_value;
        }
        length = sw_snprintf(message, sizeof(message), ":" ZEND_LONG_FMT "\r\n", zval_get_long(value));
        RETURN_STRINGL(message, length);
    } else if (type == Redis::REPLY_STRING) {
        if (!value) {
        _no_value:
            php_swoole_fatal_error(E_WARNING, "require more parameters");
            RETURN_FALSE;
        }
        zend::String str_value(value);
        if (str_value.len() > SW_REDIS_MAX_STRING_SIZE || str_value.len() < 1) {
            php_swoole_fatal_error(E_WARNING, "invalid string size");
            RETURN_FALSE;
        }
        format_buffer->clear();
        length = sw_snprintf(message, sizeof(message), "$%zu\r\n", str_value.len());
        format_buffer->append(message, length);
        format_buffer->append(str_value.val(), str_value.len());
        format_buffer->append(SW_CRLF, SW_CRLF_LEN);
        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    } else if (type == Redis::REPLY_SET) {
        if (!value) {
            goto _no_value;
        }
        if (!ZVAL_IS_ARRAY(value)) {
            php_swoole_fatal_error(E_WARNING, "the second parameter should be an array");
        }
        format_buffer->clear();
        length = sw_snprintf(message, sizeof(message), "*%d\r\n", zend_hash_num_elements(Z_ARRVAL_P(value)));
        format_buffer->append(message, length);

        zval *item;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(value), item)
        zend::String str_value(item);
        length = sw_snprintf(message, sizeof(message), "$%zu\r\n", str_value.len());
        format_buffer->append(message, length);
        format_buffer->append(str_value.val(), str_value.len());
        format_buffer->append(SW_CRLF, SW_CRLF_LEN);
        SW_HASHTABLE_FOREACH_END();

        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    } else if (type == Redis::REPLY_MAP) {
        if (!value) {
            goto _no_value;
        }
        if (!ZVAL_IS_ARRAY(value)) {
            php_swoole_fatal_error(E_WARNING, "the second parameter should be an array");
        }
        format_buffer->clear();
        length = sw_snprintf(message, sizeof(message), "*%d\r\n", 2 * zend_hash_num_elements(Z_ARRVAL_P(value)));
        format_buffer->append(message, length);

        char *key;
        uint32_t keylen;
        int keytype;
        zval *item;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(value), key, keylen, keytype, item)
        if (key == nullptr || keylen == 0) {
            continue;
        }
        zend::String str_value(item);
        length = sw_snprintf(message, sizeof(message), "$%d\r\n%s\r\n$%zu\r\n", keylen, key, str_value.len());
        format_buffer->append(message, length);
        format_buffer->append(str_value.val(), str_value.len());
        format_buffer->append(SW_CRLF, SW_CRLF_LEN);
        (void) keytype;
        SW_HASHTABLE_FOREACH_END();

        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    } else {
        php_swoole_error(E_WARNING, "Unknown type[" ZEND_LONG_FMT "]", type);
        RETURN_FALSE;
    }
}
