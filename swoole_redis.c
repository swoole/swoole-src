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

#ifdef SW_USE_REDIS
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#define SW_REDIS_COMMAND_BUFFER_SIZE   64
#define SW_REDIS_COMMAND_KEY_SIZE      128

typedef struct
{
    redisAsyncContext *context;
    uint8_t state;
    uint8_t subscribe;
    uint8_t connecting;
    uint32_t reqnum;

    zval *object;
    zval *message_callback;

#if PHP_MAJOR_VERSION >= 7
    zval _message_callback;
    zval _object;
#endif

} swRedisClient;

enum swoole_redis_state
{
    SWOOLE_REDIS_STATE_CONNECT,
    SWOOLE_REDIS_STATE_READY,
    SWOOLE_REDIS_STATE_WAIT_RESULT,
    SWOOLE_REDIS_STATE_SUBSCRIBE,
    SWOOLE_REDIS_STATE_CLOSED,
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_connect, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_call, 0, 0, 2)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_redis, __construct);
static PHP_METHOD(swoole_redis, __destruct);
static PHP_METHOD(swoole_redis, on);
static PHP_METHOD(swoole_redis, connect);
static PHP_METHOD(swoole_redis, __call);
static PHP_METHOD(swoole_redis, close);

static void swoole_redis_onConnect(const redisAsyncContext *c, int status);
static void swoole_redis_onClose(const redisAsyncContext *c, int status);
static int swoole_redis_onRead(swReactor *reactor, swEvent *event);
static int swoole_redis_onWrite(swReactor *reactor, swEvent *event);
static int swoole_redis_onError(swReactor *reactor, swEvent *event);
static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata);
static void swoole_redis_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC);

static void swoole_redis_event_AddRead(void *privdata);
static void swoole_redis_event_AddWrite(void *privdata);
static void swoole_redis_event_DelRead(void *privdata);
static void swoole_redis_event_DelWrite(void *privdata);
static void swoole_redis_event_Cleanup(void *privdata);

static zend_class_entry swoole_redis_ce;
static zend_class_entry *swoole_redis_class_entry_ptr;
static int isset_event_callback = 0;

static const zend_function_entry swoole_redis_methods[] =
{
    PHP_ME(swoole_redis, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_redis, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_redis, on, arginfo_swoole_redis_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, connect, arginfo_swoole_redis_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, __call, arginfo_swoole_redis_call, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static sw_inline int swoole_redis_is_message_command(char *command, int command_len)
{
    if (strncasecmp("subscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("psubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("unsubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("punsubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else
    {
        return SW_FALSE;
    }
}

void swoole_redis_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_redis_ce, "swoole_redis", "Swoole\\Redis", swoole_redis_methods);
    swoole_redis_class_entry_ptr = zend_register_internal_class(&swoole_redis_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_redis, "Swoole\\Redis");
}

static PHP_METHOD(swoole_redis, __construct)
{
    swRedisClient *redis = emalloc(sizeof(swRedisClient));
    bzero(redis, sizeof(swRedisClient));

    redis->object = getThis();
    sw_copy_to_stack(redis->object, redis->_object);

    swoole_set_object(getThis(), redis);
}

static PHP_METHOD(swoole_redis, on)
{
    char *name;
    zend_size_t len;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sz", &name, &len, &cb) == FAILURE)
    {
        return;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (redis->context != NULL)
    {
        swoole_php_fatal_error(E_WARNING, "Must be called before connect.");
        RETURN_FALSE;
    }

    if (strncasecmp("close", name, len) == 0)
    {
        zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onClose"), cb TSRMLS_CC);
    }
    else if (strncasecmp("message", name, len) == 0)
    {
        zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), cb TSRMLS_CC);
        redis->message_callback = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), 0 TSRMLS_CC);
        sw_copy_to_stack(redis->message_callback, redis->_message_callback);

        redis->subscribe = 1;
    }
    else
    {
        swoole_php_error(E_WARNING, "Unknown event type[%s]", name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis, connect)
{
    char *host;
    zend_size_t host_len;
    long port;
    zval *callback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &host, &host_len, &port, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (host_len <= 0)
    {
        swoole_php_error(E_WARNING, "host is empty.");
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    redisAsyncContext *context;

    if (strncasecmp(host, ZEND_STRL("unix:/")) == 0)
    {
        context = redisAsyncConnectUnix(host + 5);
    }
    else
    {
        if (port <= 1 || port > 65535)
        {
            swoole_php_error(E_WARNING, "port is invalid.");
            RETURN_FALSE;
        }
        context = redisAsyncConnect(host, (int) port);
    }

    if (context->err)
    {
        swoole_php_error(E_WARNING, "connect to redis-server[%s:%d] failed, Erorr: %s[%d]", host, (int) port, context->errstr, context->err);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!isset_event_callback)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_READ, swoole_redis_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE, swoole_redis_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_ERROR, swoole_redis_onError);
        isset_event_callback = 1;
    }

    redisAsyncSetConnectCallback(context, swoole_redis_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_onClose);

    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("sock"), context->c.fd TSRMLS_CC);
    zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), callback TSRMLS_CC);

    redis->context = context;
    context->ev.addRead = swoole_redis_event_AddRead;
    context->ev.delRead = swoole_redis_event_DelRead;
    context->ev.addWrite = swoole_redis_event_AddWrite;
    context->ev.delWrite = swoole_redis_event_DelWrite;
    context->ev.cleanup = swoole_redis_event_Cleanup;
    context->ev.data = redis;

    zend_update_property_string(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("host"), host TSRMLS_CC);
    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, redis->context->c.fd, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed. Erorr: %s[%d].", redis->context->errstr, redis->context->err);
        RETURN_FALSE;
    }

    sw_zval_add_ref(&redis->object);

    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    conn->object = redis;
}

static PHP_METHOD(swoole_redis, close)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if (redis && redis->context)
    {
        if (redis->connecting)
        {
            swoole_php_fatal_error(E_WARNING, "redis client is connecting, cannot close.");
            RETURN_FALSE;
        }
        else if (redis->state != SWOOLE_REDIS_STATE_CLOSED)
        {
            redisAsyncDisconnect(redis->context);
        }
    }

}

static PHP_METHOD(swoole_redis, __destruct)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if (redis && redis->context && redis->state != SWOOLE_REDIS_STATE_CLOSED)
    {
        redisAsyncDisconnect(redis->context);
    }
    swoole_set_object(getThis(), NULL);
    efree(redis);
}

static PHP_METHOD(swoole_redis, __call)
{
    zval *params;
    char *command;
    zend_size_t command_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &command, &command_len, &params) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(params) != IS_ARRAY)
    {
        swoole_php_fatal_error(E_WARNING, "invalid params.");
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_redis.");
        RETURN_FALSE;
    }

    switch (redis->state)
    {
    case SWOOLE_REDIS_STATE_CONNECT:
        swoole_php_error(E_WARNING, "redis client is not connected.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_STATE_WAIT_RESULT:
        if (swoole_redis_is_message_command(command, command_len))
        {
            swoole_php_error(E_WARNING, "redis client is waiting for response.");
            RETURN_FALSE;
        }
        break;
    case SWOOLE_REDIS_STATE_SUBSCRIBE:
        if (!swoole_redis_is_message_command(command, command_len))
        {
            swoole_php_error(E_WARNING, "redis client is waiting for subscribe message.");
            RETURN_FALSE;
        }
        break;
    case SWOOLE_REDIS_STATE_CLOSED:
        swoole_php_error(E_WARNING, "redis client connection is closed.");
        RETURN_FALSE;
        break;
    default:
        break;
    }

    int argc = zend_hash_num_elements(Z_ARRVAL_P(params));
    size_t stack_argvlen[SW_REDIS_COMMAND_BUFFER_SIZE];
    char *stack_argv[SW_REDIS_COMMAND_BUFFER_SIZE];

    size_t *argvlen;
    char **argv;
    zend_bool free_mm = 0;

    if (argc > SW_REDIS_COMMAND_BUFFER_SIZE)
    {
        argvlen = emalloc(sizeof(size_t) * argc);
        argv = emalloc(sizeof(char*) * argc);
        free_mm = 1;
    }
    else
    {
        argvlen = stack_argvlen;
        argv = stack_argv;
    }
#define FREE_MEM() do {                 \
    for (i = 1; i < argc; i++)          \
    {                                   \
        efree((void* )argv[i]);         \
    }                                   \
                                        \
    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE) \
    {                                   \
        efree(argv[argc]);              \
    }                                   \
                                        \
    if (free_mm)                        \
    {                                   \
        efree(argvlen);                 \
        efree(argv);                    \
    }                                   \
} while (0)

    assert(command_len < SW_REDIS_COMMAND_KEY_SIZE - 1);

    char command_name[SW_REDIS_COMMAND_KEY_SIZE];
    memcpy(command_name, command, command_len);
    command_name[command_len] = '\0';

    argv[0] = command_name;
    argvlen[0] = command_len;

    zval *value;
    int i = 1;

    /**
     * subscribe command
     */
    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE || (redis->subscribe && swoole_redis_is_message_command(command, command_len)))
    {
        redis->state = SWOOLE_REDIS_STATE_SUBSCRIBE;

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            convert_to_string(value);
            argvlen[i] = (size_t) Z_STRLEN_P(value);
            argv[i] = estrndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
            if (i == argc)
            {
                break;
            }
            i++;
        SW_HASHTABLE_FOREACH_END();

        if (redisAsyncCommandArgv(redis->context, swoole_redis_onResult, NULL, argc + 1, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            swoole_php_error(E_WARNING, "redisAsyncCommandArgv() failed.");
            FREE_MEM();
            RETURN_FALSE;
        }
    }
    /**
     * storage command
     */
    else
    {
        redis->state = SWOOLE_REDIS_STATE_WAIT_RESULT;
        redis->reqnum++;

#if PHP_MAJOR_VERSION < 7
        zval *callback;
        zval **cb_tmp;
        if (zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1, (void **) &cb_tmp) == FAILURE)
        {
            swoole_php_error(E_WARNING, "index out of array.");
            FREE_MEM();
            RETURN_FALSE;
        }
        callback = *cb_tmp;
#else
        zval *callback = zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1);
        if (callback == NULL)
        {
            swoole_php_error(E_WARNING, "index out of array.");
            FREE_MEM();
            RETURN_FALSE;
        }
#endif

        sw_zval_add_ref(&callback);
        callback = sw_zval_dup(callback);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            if (i == argc)
            {
                break;
            }

            convert_to_string(value);
            argvlen[i] = (size_t) Z_STRLEN_P(value);
            argv[i] = estrndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
            i++;
        SW_HASHTABLE_FOREACH_END();

        if (redisAsyncCommandArgv(redis->context, swoole_redis_onResult, callback, argc, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            swoole_php_error(E_WARNING, "redisAsyncCommandArgv() failed.");
            FREE_MEM();
            RETURN_FALSE;
        }
    }

    FREE_MEM();
    RETURN_TRUE;
}

static void swoole_redis_set_error(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC)
{
    char *str = malloc(reply->len + 1);
    memcpy(str, reply->str, reply->len);
    str[reply->len] = 0;

    ZVAL_FALSE(return_value);
    zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), -1 TSRMLS_CC);
    zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), str TSRMLS_CC);
    free(str);
}

static void swoole_redis_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC)
{
    zval *val;
    int j;

#if PHP_MAJOR_VERSION >= 7
    zval _val;
    val = &_val;
    bzero(val, sizeof(zval));
#endif

    switch (reply->type)
    {
    case REDIS_REPLY_INTEGER:
        ZVAL_LONG(return_value, reply->integer);
        break;

    case REDIS_REPLY_ERROR:
        swoole_redis_set_error(redis, return_value, reply TSRMLS_CC);
        break;

    case REDIS_REPLY_STATUS:
        if (redis->context->err == 0)
        {
            if (reply->len > 0)
            {
                SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
            }
            else
            {
                ZVAL_TRUE(return_value);
            }
        }
        else
        {
            zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err TSRMLS_CC);
            zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr TSRMLS_CC);
        }
        break;

    case REDIS_REPLY_STRING:
        SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
        break;

    case REDIS_REPLY_ARRAY:
        array_init(return_value);
        for (j = 0; j < reply->elements; j++)
        {
#if PHP_MAJOR_VERSION < 7
            SW_ALLOC_INIT_ZVAL(val);
#endif
            swoole_redis_parse_result(redis, val, reply->element[j] TSRMLS_CC);
            add_next_index_zval(return_value, val);
        }
        break;

    case REDIS_REPLY_NIL:
    default:
        ZVAL_NULL(return_value);
        return;
    }
}

static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    redisReply *reply = r;
    if (reply == NULL)
    {
        return;
    }

    zend_bool is_subscribe = 0;
    char *callback_type;
    swRedisClient *redis = c->ev.data;
    zval *result, *retval, *callback;
    SW_MAKE_STD_ZVAL(result);

    swoole_redis_parse_result(redis, result, reply TSRMLS_CC);

    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE)
    {
        callback = redis->message_callback;
        callback_type = "Message";
        is_subscribe = 1;
    }
    else
    {
        callback = (zval *)privdata;
        callback_type = "Result";
        assert(redis->reqnum > 0 && redis->state == SWOOLE_REDIS_STATE_WAIT_RESULT);
        redis->reqnum--;
        if (redis->reqnum == 0)
        {
            redis->state = SWOOLE_REDIS_STATE_READY;
        }
    }

    zval **args[2];
    args[0] = &redis->object;
    args[1] = &result;

    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_redis callback[%s] handler error.", callback_type);
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    if (!is_subscribe)
    {
        sw_zval_free(callback);
    }
}

void swoole_redis_onConnect(const redisAsyncContext *c, int status)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    swRedisClient *redis = c->ev.data;

    zval *result, *retval;
    SW_MAKE_STD_ZVAL(result);

    if (status != REDIS_OK)
    {
        ZVAL_BOOL(result, 0);
        zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);
        redis->state = SWOOLE_REDIS_STATE_CLOSED;
    }
    else
    {
        ZVAL_BOOL(result, 1);
        redis->state = SWOOLE_REDIS_STATE_READY;
    }

    zval **args[2];

    zval *zcallback = sw_zend_read_property(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("onConnect"), 0 TSRMLS_CC);
    args[0] = &redis->object;
    args[1] = &result;
    redis->connecting = 1;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async_redis connect_callback handler error.");
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    redis->connecting = 0;
}

void swoole_redis_onClose(const redisAsyncContext *c, int status)
{
    swRedisClient *redis = c->ev.data;
    redis->state = SWOOLE_REDIS_STATE_CLOSED;

#if PHP_MAJOR_VERSION < 7
        TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zcallback = sw_zend_read_property(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("onClose"), 1 TSRMLS_CC);
    if (zcallback && !ZVAL_IS_NULL(zcallback))
    {
        zval *retval;
        zval **args[1];
        args[0] = &redis->object;
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async_redis close_callback handler error.");
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    redis->context = NULL;
    sw_zval_ptr_dtor(&redis->object);
}

static int swoole_redis_onError(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
        TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    swRedisClient *redis = event->socket->object;
    zval *zcallback = sw_zend_read_property(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("onConnect"), 0 TSRMLS_CC);

    if (!ZVAL_IS_NULL(zcallback))
    {
        const redisAsyncContext *c = redis->context;
        zval *result;
        SW_MAKE_STD_ZVAL(result);
        ZVAL_BOOL(result, 0);
        zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);

        redis->state = SWOOLE_REDIS_STATE_CLOSED;

        zval *retval;
        zval **args[2];
        args[0] = &redis->object;
        args[1] = &result;
        redis->connecting = 1;
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async_redis connect_callback handler error.");
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&result);

        redis->connecting = 0;
        retval = NULL;
        zval *zobject = redis->object;
        sw_zend_call_method_with_0_params(&zobject, swoole_redis_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    return SW_OK;
}

static void swoole_redis_event_AddRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_event_DelRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_event_AddWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

static void swoole_redis_event_DelWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

static void swoole_redis_event_Cleanup(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    redis->state = SWOOLE_REDIS_STATE_CLOSED;
    if (redis->context && SwooleG.main_reactor)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, redis->context->c.fd);
    }
}

static int swoole_redis_onRead(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    if (redis->context && SwooleG.main_reactor)
    {
        redisAsyncHandleRead(redis->context);
    }
    return SW_OK;
}

static int swoole_redis_onWrite(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    if (redis->context && SwooleG.main_reactor)
    {
        redisAsyncHandleWrite(redis->context);
    }
    return SW_OK;
}

#endif
