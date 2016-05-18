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

    zval *result_callback;
    zval *connect_callback;
    zval *close_callback;
    zval *message_callback;

#if PHP_MAJOR_VERSION >= 7
    zval _result_callback;
    zval _connect_callback;
    zval _close_callback;
    zval _message_callback;
#endif

    zval *object;
    zval _object;
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
static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata);
static void swoole_redis_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC);

static void swoole_redis_event_AddRead(void *privdata);
static void swoole_redis_event_AddWrite(void *privdata);
static void swoole_redis_event_DelRead(void *privdata);
static void swoole_redis_event_DelWrite(void *privdata);
static void swoole_redis_event_Cleanup(void *privdata);

static zend_class_entry swoole_redis_ce;
zend_class_entry *swoole_redis_class_entry_ptr;
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
}

static PHP_METHOD(swoole_redis, __construct)
{
    swRedisClient *redis = emalloc(sizeof(swRedisClient));
    bzero(redis, sizeof(swRedisClient));

#if PHP_MAJOR_VERSION < 7
    redis->object = getThis();
#else
    redis->object = &redis->_object;
    memcpy(redis->object, getThis(), sizeof(zval));
#endif
    sw_zval_add_ref(&redis->object);

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
        redis->close_callback = sw_zend_read_property(swoole_redis_class_entry_ptr,  getThis(), ZEND_STRL("onClose"), 0 TSRMLS_CC);
        sw_copy_to_stack(redis->close_callback, redis->_close_callback);
    }
    else if (strncasecmp("message", name, len) == 0)
    {
        zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), cb TSRMLS_CC);
        redis->message_callback = sw_zend_read_property(swoole_redis_class_entry_ptr,  getThis(), ZEND_STRL("onMessage"), 0 TSRMLS_CC);
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

    if (port <= 1 || port > 65535)
    {
        swoole_php_error(E_WARNING, "port is invalid.");
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    redisAsyncContext *context = redisAsyncConnect(host, (int) port);
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
        isset_event_callback = 1;
    }

    redisAsyncSetConnectCallback(context, swoole_redis_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_onClose);

    zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), callback TSRMLS_CC);
    redis->connect_callback = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), 0 TSRMLS_CC);
    sw_copy_to_stack(redis->connect_callback, redis->_connect_callback);

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

    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    conn->object = redis;
}

static PHP_METHOD(swoole_redis, close)
{
    swRedisClient *redis = swoole_get_object(getThis());
    redisAsyncDisconnect(redis->context);
}

static PHP_METHOD(swoole_redis, __destruct)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis)
    {
        return;
    }
    if (redis->state != SWOOLE_REDIS_STATE_CLOSED)
    {
        redisAsyncDisconnect(redis->context);
    }
    if (redis->message_callback)
    {
        sw_zval_ptr_dtor(&redis->message_callback);
    }
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

    swRedisClient *redis = swoole_get_object(getThis());
    switch (redis->state)
    {
    case SWOOLE_REDIS_STATE_CONNECT:
        swoole_php_error(E_WARNING, "redis client is not connected.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_STATE_WAIT_RESULT:
        swoole_php_error(E_WARNING, "redis client is waiting for response.");
        RETURN_FALSE;
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
            RETURN_FALSE;
        }
    }
    /**
     * storage command
     */
    else
    {
        redis->state = SWOOLE_REDIS_STATE_WAIT_RESULT;

#if PHP_MAJOR_VERSION < 7
        zval *callback;
        zval **cb_tmp;
        if (zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1, (void **) &cb_tmp) == FAILURE)
        {
            swoole_php_error(E_WARNING, "index out of array.");
            RETURN_FALSE;
        }
        callback = *cb_tmp;
        redis->result_callback = callback;
#else
        zval *callback = zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1);
        if (callback == NULL)
        {
            swoole_php_error(E_WARNING, "index out of array.");
            RETURN_FALSE;
        }
        redis->result_callback = &redis->_result_callback;
        memcpy(redis->result_callback, callback, sizeof(zval));
#endif

        sw_zval_add_ref(&redis->result_callback);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            convert_to_string(value);
            argvlen[i] = (size_t) Z_STRLEN_P(value);
            argv[i] = estrndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
            if (i == argc - 1)
            {
                break;
            }
            i++;
        SW_HASHTABLE_FOREACH_END();

        if (redisAsyncCommandArgv(redis->context, swoole_redis_onResult, NULL, argc, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            swoole_php_error(E_WARNING, "redisAsyncCommandArgv() failed.");
            RETURN_FALSE;
        }
    }

    for (i = 1; i < argc; i++)
    {
        efree((void* )argv[i]);
    }

    if (free_mm)
    {
        efree(argvlen);
        efree(argv);
    }

    RETURN_TRUE;
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
        ZVAL_FALSE(return_value);
        zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr TSRMLS_CC);
        break;

    case REDIS_REPLY_STATUS:
        if (redis->context->err == 0)
        {
            ZVAL_TRUE(return_value);
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

    char *callback_type;
    swRedisClient *redis = c->ev.data;
    zval *result, *retval, *callback;
    SW_MAKE_STD_ZVAL(result);

    swoole_redis_parse_result(redis, result, reply TSRMLS_CC);

    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE)
    {
        callback = redis->message_callback;
        callback_type = "Message";
    }
    else
    {
        callback = redis->result_callback;
        callback_type = "Result";
        redis->state = SWOOLE_REDIS_STATE_READY;
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

#if PHP_MAJOR_VERSION < 7
    if (redis->state == SWOOLE_REDIS_STATE_READY)
    {
        sw_zval_ptr_dtor(&callback);
    }
#endif
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
    zval *callback = redis->connect_callback;
    args[0] = &redis->object;
    args[1] = &result;

    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback handler error.");
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    sw_zval_ptr_dtor(&callback);
}

void swoole_redis_onClose(const redisAsyncContext *c, int status)
{
    swRedisClient *redis = c->ev.data;
    redis->state = SWOOLE_REDIS_STATE_CLOSED;
}

static void swoole_redis_event_AddRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
}

static void swoole_redis_event_DelRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
}

static void swoole_redis_event_AddWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
}

static void swoole_redis_event_DelWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
}

static void swoole_redis_event_Cleanup(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    SwooleG.main_reactor->del(SwooleG.main_reactor, redis->context->c.fd);

    if (redis->close_callback)
    {
#if PHP_MAJOR_VERSION < 7
        TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
        zval *retval;
        zval **args[1];
        args[0] = &redis->object;

        if (sw_call_user_function_ex(EG(function_table), NULL, redis->connect_callback, &retval, 1, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback handler error.");
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
}

static int swoole_redis_onRead(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    redisAsyncHandleRead(redis->context);
    return SW_OK;
}

static int swoole_redis_onWrite(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    redisAsyncHandleWrite(redis->context);
    return SW_OK;
}

#endif
