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

typedef struct
{
    redisAsyncContext *context;
    uint8_t state;
    zval *result_callback;
    zval _result_callback;
    zval *connect_callback;
    zval _connect_callback;
    zval *object;
} swRedisClient;

enum swoole_redis_state
{
    SWOOLE_REDIS_STATE_CONNECT,
    SWOOLE_REDIS_STATE_READY,
    SWOOLE_REDIS_STATE_WAIT,
    SWOOLE_REDIS_STATE_CLOSED,
};

static PHP_METHOD(swoole_redis, connect);
static PHP_METHOD(swoole_redis, close);
static PHP_METHOD(swoole_redis, execute);
static PHP_METHOD(swoole_redis, __destruct);

static void swoole_redis_onConnect(const redisAsyncContext *c, int status);
static void swoole_redis_onClose(const redisAsyncContext *c, int status);
static int swoole_redis_onRead(swReactor *reactor, swEvent *event);
static int swoole_redis_onWrite(swReactor *reactor, swEvent *event);
static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata);

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
    PHP_ME(swoole_redis, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, execute, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_FE_END
};

void swoole_redis_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_redis_ce, "swoole_redis", swoole_redis_methods);
    swoole_redis_class_entry_ptr = zend_register_internal_class(&swoole_redis_ce TSRMLS_CC);
}

static PHP_METHOD(swoole_redis, connect)
{
    char *host = "127.0.0.1";
    int host_len;
    long port = 6379;
    zval *callback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &host, &host_len, &port, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    redisAsyncContext *context = redisAsyncConnect(host, (int) port);
    if (context->err)
    {
        swoole_php_error(E_WARNING, "connect to redis-server[%s:%d] failed, Erorr: %s[%d]", host, (int) port, context->errstr, context->err);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!isset_event_callback)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_SWOOLE_REDIS | SW_EVENT_READ, swoole_redis_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_SWOOLE_REDIS | SW_EVENT_WRITE, swoole_redis_onWrite);
        isset_event_callback = 1;
    }

    redisAsyncSetConnectCallback(context, swoole_redis_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_onClose);

    swRedisClient *redis = emalloc(sizeof(swRedisClient));
    bzero(redis, sizeof(swRedisClient));

#if PHP_MAJOR_VERSION < 7
    redis->connect_callback = callback;
#else
    redis->connect_callback = &redis->_connect_callback;
    memcpy(redis->connect_callback, callback, sizeof(zval));
#endif

    sw_zval_add_ref(&redis->connect_callback);

    redis->context = context;
    redis->object = getThis();

    context->ev.addRead = swoole_redis_event_AddRead;
    context->ev.delRead = swoole_redis_event_DelRead;
    context->ev.addWrite = swoole_redis_event_AddWrite;
    context->ev.delWrite = swoole_redis_event_DelWrite;
    context->ev.cleanup = swoole_redis_event_Cleanup;
    context->ev.data = redis;

    swoole_set_object(getThis(), redis);

    zend_update_property_string(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("host"), host TSRMLS_CC);
    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, redis->context->c.fd, SW_FD_SWOOLE_REDIS | SW_EVENT_WRITE) < 0)
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
    if (redis->state != SWOOLE_REDIS_STATE_CLOSED)
    {
        redisAsyncDisconnect(redis->context);
    }
    efree(redis);
}

static PHP_METHOD(swoole_redis, execute)
{
    zval *callback;
    char *command;
    int command_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &command, &command_len, &callback) == FAILURE)
    {
        return;
    }

    swRedisClient *redis = swoole_get_object(getThis());

    switch(redis->state)
    {
    case SWOOLE_REDIS_STATE_CONNECT:
        swoole_php_error(E_WARNING, "redis client is not connected.");
        RETVAL_FALSE;
        return;
    case SWOOLE_REDIS_STATE_WAIT:
        swoole_php_error(E_WARNING, "redis client is waiting for response.");
        RETVAL_FALSE;
        return;
    case SWOOLE_REDIS_STATE_CLOSED:
        swoole_php_error(E_WARNING, "redis client connection is closed.");
        RETVAL_FALSE;
        return;
    default:
        break;
    }

#if PHP_MAJOR_VERSION < 7
    redis->result_callback = callback;
#else
    redis->result_callback = &redis->_result_callback;
    memcpy(redis->result_callback, callback, sizeof(zval));
#endif

    sw_zval_add_ref(&redis->result_callback);
    if (redisAsyncCommand(redis->context, swoole_redis_onResult, NULL, command, command_len) < 0)
    {
        swoole_php_error(E_WARNING, "redisAsyncCommandArgv() failed.");
        RETURN_FALSE;
    }
    redis->state = SWOOLE_REDIS_STATE_WAIT;
    RETURN_TRUE;
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

    swRedisClient *redis = c->ev.data;
    zval *result, *retval;
    SW_MAKE_STD_ZVAL(result);

    if (reply->str == NULL)
    {
        ZVAL_BOOL(result, 0);
        zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);
    }
    else
    {
        SW_ZVAL_STRINGL(result, reply->str, reply->len, 1);
    }

    redis->state = SWOOLE_REDIS_STATE_READY;

    zval **args[2];
    args[0] = &redis->object;
    args[1] = &result;

    if (sw_call_user_function_ex(EG(function_table), NULL, redis->result_callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback handler error.");
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
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
    args[0] = &redis->object;
    args[1] = &result;

    if (sw_call_user_function_ex(EG(function_table), NULL, redis->connect_callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback handler error.");
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
}

void swoole_redis_onClose(const redisAsyncContext *c, int status)
{
    swRedisClient *redis = c->ev.data;
    redis->state = SWOOLE_REDIS_STATE_CLOSED;
}

static void swoole_redis_event_AddRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    if (!(conn->events & SW_EVENT_READ))
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, redis->context->c.fd, conn->fdtype | conn->events | SW_EVENT_READ);
    }
}

static void swoole_redis_event_DelRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    if (conn->events & SW_EVENT_READ)
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, redis->context->c.fd, conn->fdtype | (conn->events & (~SW_EVENT_READ)));
    }
}

static void swoole_redis_event_AddWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);

    if (!(conn->events & SW_EVENT_WRITE))
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, redis->context->c.fd, conn->fdtype | conn->events | SW_EVENT_WRITE);
    }
}

static void swoole_redis_event_DelWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    if (conn->events & SW_EVENT_WRITE)
    {
        SwooleG.main_reactor->set(SwooleG.main_reactor, redis->context->c.fd, conn->fdtype | (conn->events & (~SW_EVENT_WRITE)));
    }
}

static void swoole_redis_event_Cleanup(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    SwooleG.main_reactor->del(SwooleG.main_reactor, redis->context->c.fd);
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
