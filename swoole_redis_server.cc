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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "redis.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#endif
BEGIN_EXTERN_C()
#include "ext/standard/php_string.h"
END_EXTERN_C()

static zend_class_entry swoole_redis_server_ce;
static zend_class_entry *swoole_redis_server_ce_ptr;
static zend_object_handlers swoole_redis_server_handlers;

static swString *format_buffer;
#ifdef SW_COROUTINE
static struct
{
    zend_fcall_info_cache **array;
    uint32_t size;
    uint32_t count;
} func_cache_array = {NULL, 0, 0};
#endif

static PHP_METHOD(swoole_redis_server, start);
static PHP_METHOD(swoole_redis_server, setHandler);
static PHP_METHOD(swoole_redis_server, format);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_start, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_setHandler, 0, 0, 2)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, number_of_string_param)
    ZEND_ARG_INFO(0, type_of_array_param)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_server_format, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_redis_server_methods[] =
{
    PHP_ME(swoole_redis_server, start, arginfo_swoole_redis_server_start, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, setHandler, arginfo_swoole_redis_server_setHandler, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_server, format, arginfo_swoole_redis_server_format, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_redis_server_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY_EX(swoole_redis_server, "Swoole\\Redis\\Server", "swoole_redis_server", NULL, swoole_redis_server_methods, swoole_server);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_redis_server, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_redis_server, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_redis_server, zend_class_unset_property_deny);

    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("NIL"), SW_REDIS_REPLY_NIL);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("ERROR"), SW_REDIS_REPLY_ERROR);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("STATUS"), SW_REDIS_REPLY_STATUS);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("INT"), SW_REDIS_REPLY_INT);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("STRING"), SW_REDIS_REPLY_STRING);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("SET"), SW_REDIS_REPLY_SET);
    zend_declare_class_constant_long(swoole_redis_server_ce_ptr, ZEND_STRL("MAP"), SW_REDIS_REPLY_MAP);
}

static int redis_onReceive(swServer *serv, swEventData *req)
{
    int fd = req->info.fd;
    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        swWarn("connection[%d] is closed.", fd);
        return SW_ERR;
    }

    swListenPort *port = (swListenPort *) serv->connection_list[req->info.from_fd].object;
    //other server port
    if (!port->open_redis_protocol)
    {
        return php_swoole_onReceive(serv, req);
    }

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    php_swoole_get_recv_data(zdata, req, NULL, 0);
    char *p = Z_STRVAL_P(zdata);
    char *pe = p + Z_STRLEN_P(zdata);
    int ret;
    int length = 0;

    zval *zparams;
    SW_MAKE_STD_ZVAL(zparams);
    array_init(zparams);

    zval *retval = NULL;

    int state = SW_REDIS_RECEIVE_TOTAL_LINE;
    int add_param = 0;
    char *command = NULL;
    int command_len = 0;

    do
    {
        switch (state)
        {
        case SW_REDIS_RECEIVE_TOTAL_LINE:
            if (*p == '*' && (p = swRedis_get_number(p, &ret)))
            {
                state = SW_REDIS_RECEIVE_LENGTH;
                break;
            }
            /* no break */

        case SW_REDIS_RECEIVE_LENGTH:
            if (*p == '$' && (p = swRedis_get_number(p, &ret)))
            {
                if (ret == -1)
                {
                    add_next_index_null(zparams);
                    break;
                }
                length = ret;
                state = SW_REDIS_RECEIVE_STRING;
                break;
            }
            //integer
            else if (*p == ':' && (p = swRedis_get_number(p, &ret)))
            {
                add_next_index_long(zparams, ret);
                break;
            }
            /* no break */

        case SW_REDIS_RECEIVE_STRING:
            if (add_param == 0)
            {
                command = p;
                command_len = length;
                add_param = 1;
            }
            else
            {
                add_next_index_stringl(zparams, p, length);
            }
            p += length + SW_CRLF_LEN;
            state = SW_REDIS_RECEIVE_LENGTH;
            break;

        default:
            break;
        }
    } while(p < pe);

    if (command_len >= SW_REDIS_MAX_COMMAND_SIZE)
    {
        swoole_php_error(E_WARNING, "command is too long.");
        serv->close(serv, fd, 0);
        return SW_OK;
    }

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    command[command_len] = 0;
    int _command_len = snprintf(_command, sizeof(_command), "_handler_%*s", command_len, command);
    php_strtolower(_command, _command_len);

    zval *zobject = (zval *) serv->ptr2;
    char err_msg[256];

    zval *zfd;
    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, fd);

    zval args[2];
    args[0] = *zfd;
    args[1] = *zparams;

    if (SwooleG.enable_coroutine)
    {
        zval *zindex = sw_zend_read_property(swoole_redis_server_ce_ptr, zobject, _command, _command_len, 1);
        if (!zindex || ZVAL_IS_NULL(zindex))
        {
            length = snprintf(err_msg, sizeof(err_msg), "-ERR unknown command '%*s'\r\n", command_len, command);
            swServer_tcp_send(serv, fd, err_msg, length);
            return SW_OK;
        }

        zend_fcall_info_cache *cache = func_cache_array.array[Z_LVAL_P(zindex)];
        if (sw_coro_create(cache, 2, args, retval) < 0)
        {
            zval_ptr_dtor(zfd);
            zval_ptr_dtor(zdata);
            zval_ptr_dtor(zparams);
            return SW_OK;
        }
    }
    else
    {
        zval *zcallback = sw_zend_read_property(swoole_redis_server_ce_ptr, zobject, _command, _command_len, 1);
        if (!zcallback || ZVAL_IS_NULL(zcallback))
        {
            length = snprintf(err_msg, sizeof(err_msg), "-ERR unknown command '%*s'\r\n", command_len, command);
            swServer_tcp_send(serv, fd, err_msg, length);
            return SW_OK;
        }

        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL) == FAILURE)
        {
            swoole_php_error(E_WARNING, "command handler error.");
        }
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    //free the callback return value
    if (retval)
    {
        if (Z_TYPE_P(retval) == IS_STRING)
        {
            serv->send(serv, fd, Z_STRVAL_P(retval), Z_STRLEN_P(retval));
        }
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zfd);
    zval_ptr_dtor(zdata);
    zval_ptr_dtor(zparams);
    return SW_OK;
}

static PHP_METHOD(swoole_redis_server, start)
{
    int ret;

    swServer *serv = (swServer *) swoole_get_object(getThis());
    if (serv->gs->start > 0)
    {
        swoole_php_error(E_WARNING, "Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    php_swoole_register_callback(serv);

    serv->onReceive = redis_onReceive;

    format_buffer = swString_new(SW_BUFFER_SIZE_STD);
    if (!format_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_BUFFER_SIZE_STD);
        RETURN_FALSE;
    }

    zval *zsetting = sw_zend_read_property(swoole_server_ce_ptr, getThis(), ZEND_STRL("setting"), 1);
    if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
    {
        SW_ALLOC_INIT_ZVAL(zsetting);
        array_init(zsetting);
        zend_update_property(swoole_server_ce_ptr, getThis(), ZEND_STRL("setting"), zsetting);
    }

#ifdef HT_ALLOW_COW_VIOLATION
    HT_ALLOW_COW_VIOLATION(Z_ARRVAL_P(zsetting));
#endif

    add_assoc_bool(zsetting, "open_http_protocol", 0);
    add_assoc_bool(zsetting, "open_mqtt_protocol", 0);
    add_assoc_bool(zsetting, "open_eof_check", 0);
    add_assoc_bool(zsetting, "open_length_check", 0);
    add_assoc_bool(zsetting, "open_redis_protocol", 0);

    serv->listen_list->open_http_protocol = 0;
    serv->listen_list->open_mqtt_protocol = 0;
    serv->listen_list->open_eof_check = 0;
    serv->listen_list->open_length_check = 0;
    serv->listen_list->open_redis_protocol = 1;

    php_swoole_server_before_start(serv, getThis());

    ret = swServer_start(serv);
    if (ret < 0)
    {
        swoole_php_fatal_error(E_ERROR, "server failed to start. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_server, setHandler)
{
    char *command;
    size_t command_len;
    zval *zcallback;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &command, &command_len, &zcallback) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (command_len <= 0 || command_len >= SW_REDIS_MAX_COMMAND_SIZE)
    {
        swoole_php_fatal_error(E_ERROR, "invalid command.");
        RETURN_FALSE;
    }

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (func_cache_array.array == NULL)
    {
        func_cache_array.array = (zend_fcall_info_cache **) ecalloc(32, sizeof(zend_fcall_info_cache *));
        func_cache_array.size = 32;
        func_cache_array.count = 0;
    }
    zend_fcall_info_cache *func_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(zcallback, NULL, 0, &func_name, NULL, func_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
#endif

    char _command[SW_REDIS_MAX_COMMAND_SIZE];
    int length = snprintf(_command, sizeof(_command), "_handler_%s", command);
    php_strtolower(_command, length);

    int func_cache_index = func_cache_array.count;
    func_cache_array.array[func_cache_index] = func_cache;
    func_cache_array.count++;
    if (func_cache_array.count == func_cache_array.size)
    {
        func_cache_array.size *= 2;
        func_cache_array.array = (zend_fcall_info_cache **) ecalloc(func_cache_array.size, sizeof(zend_fcall_info_cache *));
    }
    Z_TRY_ADDREF_P(zcallback);
    zend_update_property_long(swoole_redis_server_ce_ptr, getThis(), _command, length, func_cache_index);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_server, format)
{
    long type;
    zval *value = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|z", &type, &value) == FAILURE)
    {
        RETURN_FALSE;
    }

    char message[256];
    int length;
    zval *item;

    if (type == SW_REDIS_REPLY_NIL)
    {
        RETURN_STRINGL(SW_REDIS_RETURN_NIL, sizeof(SW_REDIS_RETURN_NIL)-1);
    }
    else if (type == SW_REDIS_REPLY_STATUS)
    {
        if (value)
        {
            convert_to_string(value);
            length = snprintf(message, sizeof(message), "+%*s\r\n", (int)Z_STRLEN_P(value), Z_STRVAL_P(value));
        }
        else
        {
            length = snprintf(message, sizeof(message), "+%s\r\n", "OK");
        }
        RETURN_STRINGL(message, length);
    }
    else if (type == SW_REDIS_REPLY_ERROR)
    {
        if (value)
        {
            convert_to_string(value);
            length = snprintf(message, sizeof(message), "-%*s\r\n", (int)Z_STRLEN_P(value), Z_STRVAL_P(value));
        }
        else
        {
            length = snprintf(message, sizeof(message), "-%s\r\n", "ERR");
        }
        RETURN_STRINGL(message, length);
    }
    else if (type == SW_REDIS_REPLY_INT)
    {
        if (!value)
        {
            goto no_value;
        }

        convert_to_long(value);
        length = snprintf(message, sizeof(message), ":" ZEND_LONG_FMT "\r\n", Z_LVAL_P(value));
        RETURN_STRINGL(message, length);
    }
    else if (type == SW_REDIS_REPLY_STRING)
    {
        if (!value)
        {
            no_value:
            swoole_php_fatal_error(E_WARNING, "require more parameters.");
            RETURN_FALSE;
        }
        convert_to_string(value);
        if (Z_STRLEN_P(value) > SW_REDIS_MAX_STRING_SIZE || Z_STRLEN_P(value) < 1)
        {
            swoole_php_fatal_error(E_WARNING, "invalid string size.");
            RETURN_FALSE;
        }
        swString_clear(format_buffer);
        length = snprintf(message, sizeof(message), "$%zd\r\n", Z_STRLEN_P(value));
        swString_append_ptr(format_buffer, message, length);
        swString_append_ptr(format_buffer, Z_STRVAL_P(value), Z_STRLEN_P(value));
        swString_append_ptr(format_buffer, SW_CRLF, SW_CRLF_LEN);
        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    }
    else if (type == SW_REDIS_REPLY_SET)
    {
        if (!value)
        {
            goto no_value;
        }
        if (Z_TYPE_P(value) != IS_ARRAY)
        {
            swoole_php_fatal_error(E_WARNING, "the second parameter should be an array.");
        }
        swString_clear(format_buffer);
        length = snprintf(message, sizeof(message), "*%d\r\n", zend_hash_num_elements(Z_ARRVAL_P(value)));
        swString_append_ptr(format_buffer, message, length);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(value), item)
            zval _copy;
            if (Z_TYPE_P(item) != IS_STRING)
            {
                _copy = *item;
                zval_copy_ctor(&_copy);
                item = &_copy;
            }
            convert_to_string(item);
            length = snprintf(message, sizeof(message), "$%zd\r\n", Z_STRLEN_P(item));
            swString_append_ptr(format_buffer, message, length);
            swString_append_ptr(format_buffer, Z_STRVAL_P(item), Z_STRLEN_P(item));
            swString_append_ptr(format_buffer, SW_CRLF, SW_CRLF_LEN);
            if (item == &_copy)
            {
                zval_dtor(item);
            }
        SW_HASHTABLE_FOREACH_END();

        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    }
    else if (type == SW_REDIS_REPLY_MAP)
    {
        if (!value)
        {
            goto no_value;
        }
        if (Z_TYPE_P(value) != IS_ARRAY)
        {
            swoole_php_fatal_error(E_WARNING, "the second parameter should be an array.");
        }
        swString_clear(format_buffer);
        length = snprintf(message, sizeof(message), "*%d\r\n", 2 * zend_hash_num_elements(Z_ARRVAL_P(value)));
        swString_append_ptr(format_buffer, message, length);

        char *key;
        uint32_t keylen;
        int keytype;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(value), key, keylen, keytype, item)
            if (key == NULL || keylen <= 0)
            {
                continue;
            }
            zval _copy;
            if (Z_TYPE_P(item) != IS_STRING)
            {
                _copy = *item;
                zval_copy_ctor(&_copy);
                item = &_copy;
            }
            convert_to_string(item);
            length = snprintf(message, sizeof(message), "$%d\r\n%s\r\n$%zd\r\n", keylen, key, Z_STRLEN_P(item));
            swString_append_ptr(format_buffer, message, length);
            swString_append_ptr(format_buffer, Z_STRVAL_P(item), Z_STRLEN_P(item));
            swString_append_ptr(format_buffer, SW_CRLF, SW_CRLF_LEN);

            if (item == &_copy)
            {
                zval_dtor(item);
            }
            (void) keytype;
        SW_HASHTABLE_FOREACH_END();

        RETURN_STRINGL(format_buffer->str, format_buffer->length);
    }
    else
    {
        swoole_php_error(E_WARNING, "Unknown type[%ld]", type);
        RETURN_FALSE;
    }
}
