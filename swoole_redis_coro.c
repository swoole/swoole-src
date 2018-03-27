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

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#ifdef SW_USE_REDIS
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <ext/standard/php_var.h>

#if PHP_MAJOR_VERSION < 7
#include <ext/standard/php_smart_str.h>
#define SW_REDIS_COMMAND_ALLOC_ARGS_ARR zval **z_args = emalloc(argc*sizeof(zval*));
#define SW_REDIS_COMMAND_ARGS_TYPE(arg) Z_TYPE_P(arg)
#define SW_REDIS_COMMAND_ARGS_LVAL(arg) Z_LVAL_P(arg)
#define SW_REDIS_COMMAND_ARGS_DVAL(arg) Z_DVAL_P(arg)
#define SW_REDIS_COMMAND_ARGS_ARRVAL(arg) Z_ARRVAL_P(arg)
#define SW_REDIS_COMMAND_ARGS_STRVAL(arg) Z_STRVAL_P(arg)
#define SW_REDIS_COMMAND_ARGS_STRLEN(arg) Z_STRLEN_P(arg)
#define SW_REDIS_COMMAND_ARGS_REF(arg) arg
#else
#define SW_REDIS_COMMAND_ALLOC_ARGS_ARR zval *z_args = emalloc(argc*sizeof(zval));
#define SW_REDIS_COMMAND_ARGS_TYPE(arg) Z_TYPE(arg)
#define SW_REDIS_COMMAND_ARGS_LVAL(arg) Z_LVAL(arg)
#define SW_REDIS_COMMAND_ARGS_DVAL(arg) Z_DVAL(arg)
#define SW_REDIS_COMMAND_ARGS_ARRVAL(arg) Z_ARRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRVAL(arg) Z_STRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRLEN(arg) Z_STRLEN(arg)
#define SW_REDIS_COMMAND_ARGS_REF(arg) &arg
#endif

#define SW_REDIS_COMMAND_BUFFER_SIZE   64
#define SW_BITOP_MIN_OFFSET 0
#define SW_BITOP_MAX_OFFSET 4294967295
#define SW_REDIS_NOT_FOUND 0
#define SW_REDIS_STRING    1
#define SW_REDIS_SET       2
#define SW_REDIS_LIST      3
#define SW_REDIS_ZSET      4
#define SW_REDIS_HASH      5
/* the same errCode define with hiredis */
enum swRedisError
{
    SW_REDIS_ERR_IO = 1, /* Error in read or write */
    SW_REDIS_ERR_EOF = 3,/* End of file */
    SW_REDIS_ERR_PROTOCOL = 4,/* Protocol error */
    SW_REDIS_ERR_OOM = 5,/* Out of memory */
    SW_REDIS_ERR_OTHER = 2,/* Everything else... */
    SW_REDIS_ERR_CLOSED = 6, /* Everything else... */
};

/* Extended SET argument detection */
#define IS_EX_ARG(a) \
    ((a[0]=='e' || a[0]=='E') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_PX_ARG(a) \
    ((a[0]=='p' || a[0]=='P') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_NX_ARG(a) \
    ((a[0]=='n' || a[0]=='N') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_XX_ARG(a) \
    ((a[0]=='x' || a[0]=='X') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')

static zend_class_entry swoole_redis_coro_ce;
static zend_class_entry *swoole_redis_coro_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_connect, 0, 0, 2)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, serialize)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, config)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_key, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_key_value, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_key_long, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, integer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_key_opt_long, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, integer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_request, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_incrByFloat, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, float_number)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zIncrBy, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, withscores)
ZEND_END_ARG_INFO()

#define IS_EX_PX_ARG(a) (IS_EX_ARG(a) || IS_PX_ARG(a))
#define IS_NX_XX_ARG(a) (IS_NX_ARG(a) || IS_XX_ARG(a))

#define SW_REDIS_COMMAND_CHECK \
    coro_check(TSRMLS_C);\
    swRedisClient *redis = swoole_get_object(getThis()); \
    if (!redis)\
    {\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_CLOSED TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is waiting for response." TSRMLS_CC); \
        RETURN_FALSE;\
    }\
	if (redis->iowait == SW_REDIS_CORO_STATUS_WAIT) \
	{ \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for response." TSRMLS_CC); \
        RETURN_FALSE; \
	} \
	if (redis->iowait == SW_REDIS_CORO_STATUS_DONE) \
	{ \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for calling recv." TSRMLS_CC); \
        RETURN_FALSE; \
	} \
    switch (redis->state) \
    { \
    case SWOOLE_REDIS_CORO_STATE_CONNECT: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is not connected." TSRMLS_CC); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for subscribe message." TSRMLS_CC); \
		RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_CLOSED: \
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client connection is closed." TSRMLS_CC); \
        RETURN_FALSE; \
        break; \
    default: \
        break; \
    }\
    if (unlikely(redis->cid && redis->cid != get_current_cid()))\
    {\
        swoole_php_fatal_error(E_WARNING, "redis client has already been bound to another coroutine.");\
        RETURN_FALSE;\
    }

#define SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS \
    coro_check(TSRMLS_C);\
    swRedisClient *redis = swoole_get_object(getThis()); \
    if (!redis)\
    {\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_CLOSED TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is waiting for response." TSRMLS_CC); \
        RETURN_FALSE;\
    }\
	if (redis->iowait == SW_REDIS_CORO_STATUS_WAIT) \
	{ \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for response." TSRMLS_CC); \
		efree(z_args); \
        RETURN_FALSE; \
	} \
	if (redis->iowait == SW_REDIS_CORO_STATUS_DONE) \
	{ \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for calling recv." TSRMLS_CC); \
        RETURN_FALSE; \
	} \
    switch (redis->state) \
    { \
    case SWOOLE_REDIS_CORO_STATE_CONNECT: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is not connected." TSRMLS_CC); \
		efree(z_args); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for subscribe message." TSRMLS_CC); \
		efree(z_args); \
		RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_CLOSED: \
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client connection is closed." TSRMLS_CC); \
		efree(z_args); \
        RETURN_FALSE; \
        break; \
    default: \
        break; \
    }

#define SW_REDIS_COMMAND_YIELD \
	if (redis->state == SWOOLE_REDIS_CORO_STATE_MULTI || redis->state == SWOOLE_REDIS_CORO_STATE_PIPELINE) \
	{ \
		redis->queued_cmd_count++; \
		RETURN_ZVAL(getThis(), 1, 0); \
	} \
	else \
	{ \
		redis->iowait = SW_REDIS_CORO_STATUS_WAIT; \
		if (redis->defer) \
		{ \
			RETURN_TRUE; \
		} \
		redis->cid = get_current_cid();\
		php_context *context = swoole_get_property(getThis(), 0); \
		coro_save(context); \
		coro_yield(); \
	}

#define SW_REDIS_COMMAND_ARGV_FILL(str, str_len) \
	argvlen[i] = str_len; \
	argv[i] = estrndup(str, str_len); \
	i++;
#if (PHP_MAJOR_VERSION < 7)
#define SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(_val) \
	if (redis->serialize) { \
		smart_str sstr = {0}; \
		php_serialize_data_t s_ht; \
		PHP_VAR_SERIALIZE_INIT(s_ht); \
		php_var_serialize(&sstr, &_val, &s_ht TSRMLS_CC); \
		argvlen[i] = (size_t)sstr.len; \
		argv[i] = sstr.c; \
		PHP_VAR_SERIALIZE_DESTROY(s_ht); \
	} else { \
		convert_to_string(_val); \
		argvlen[i] = Z_STRLEN_P(_val); \
		argv[i] = estrndup(Z_STRVAL_P(_val), argvlen[i]); \
	} \
	i++;
#else
#define SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(_val) \
	if (redis->serialize) { \
		smart_str sstr = {0}; \
		php_serialize_data_t s_ht; \
		PHP_VAR_SERIALIZE_INIT(s_ht); \
		php_var_serialize(&sstr, _val, &s_ht TSRMLS_CC); \
		argvlen[i] = (size_t)sstr.s->len; \
		argv[i] = estrndup(sstr.s->val, sstr.s->len); \
        zend_string_release(sstr.s); \
		PHP_VAR_SERIALIZE_DESTROY(s_ht); \
	} else { \
        zend_string *convert_str = zval_get_string(_val); \
        argvlen[i] = convert_str->len; \
        argv[i] = estrndup(convert_str->val, convert_str->len); \
        zend_string_release(convert_str); \
	} \
	i++;
#endif

#define SW_REDIS_COMMAND_ALLOC_ARGV \
    size_t stack_argvlen[SW_REDIS_COMMAND_BUFFER_SIZE]; \
    char *stack_argv[SW_REDIS_COMMAND_BUFFER_SIZE]; \
    size_t *argvlen; \
    char **argv; \
    zend_bool free_mm = 0; \
    if (argc > SW_REDIS_COMMAND_BUFFER_SIZE) \
    { \
        argvlen = emalloc(sizeof(size_t) * (argc)); \
        argv = emalloc(sizeof(char*) * (argc)); \
        free_mm = 1; \
    } \
    else \
    { \
        argvlen = stack_argvlen; \
        argv = stack_argv; \
    }

#define SW_REDIS_COMMAND_FREE_ARGV \
    if (free_mm) \
    { \
        efree(argvlen); \
        efree(argv); \
    }

#define SW_REDIS_COMMAND(argc) \
    int __cmd_retval = redisAsyncCommandArgv(redis->context, swoole_redis_coro_onResult, NULL, argc, (const char **) argv, (const size_t *) argvlen);\
	if (__cmd_retval < 0) \
	{ \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed." TSRMLS_CC); \
	} \
    for (i = 0; i < argc; i++) \
    { \
        efree(argv[i]); \
    }\
    if (__cmd_retval < 0) \
    {\
        RETURN_FALSE;\
    }

typedef enum
{
    SW_REDIS_CORO_STATUS_CLOSED,
    SW_REDIS_CORO_STATUS_READY,
    SW_REDIS_CORO_STATUS_WAIT,
    SW_REDIS_CORO_STATUS_DONE,
} swoole_redis_coro_io_status;

typedef enum
{
    SWOOLE_REDIS_CORO_STATE_CONNECT,
    SWOOLE_REDIS_CORO_STATE_READY,
    SWOOLE_REDIS_CORO_STATE_SUBSCRIBE,
    SWOOLE_REDIS_CORO_STATE_MULTI,
    SWOOLE_REDIS_CORO_STATE_PIPELINE,
    SWOOLE_REDIS_CORO_STATE_CLOSED,
    SWOOLE_REDIS_CORO_STATE_CLOSING,
    SWOOLE_REDIS_CORO_STATE_RELEASED,
} swoole_redis_coro_state;

typedef struct
{
    redisAsyncContext *context;
	zend_bool defer;
	zend_bool defer_yield;
    zend_bool connecting;
    zend_bool connected;
    zend_bool released;
    swoole_redis_coro_state state;
    swoole_redis_coro_io_status iowait;
    uint16_t queued_cmd_count;
    zval *pipeline_result;
    zval *defer_result;
    zend_bool serialize;
    int cid;

    double timeout;
    swTimer_node *timer;

    zval *object;
    zval _object;

} swRedisClient;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _value;
#endif
    zval *value;
    swRedisClient *redis;
} swRedis_result;

enum {SW_REDIS_MODE_MULTI, SW_REDIS_MODE_PIPELINE};

static void swoole_redis_coro_event_AddRead(void *privdata);
static void swoole_redis_coro_event_AddWrite(void *privdata);
static void swoole_redis_coro_event_DelRead(void *privdata);
static void swoole_redis_coro_event_DelWrite(void *privdata);
static void swoole_redis_coro_event_Cleanup(void *privdata);

static void swoole_redis_coro_onTimeout(swTimer *timer, swTimer_node *tnode);

static void swoole_redis_coro_onConnect(const redisAsyncContext *c, int status);
static void swoole_redis_coro_onClose(const redisAsyncContext *c, int status);
static int swoole_redis_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_redis_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_redis_coro_onError(swReactor *reactor, swEvent *event);
static void swoole_redis_coro_onResult(redisAsyncContext *c, void *r, void *privdata);
static void swoole_redis_coro_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC);

static sw_inline void sw_redis_command_empty(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[1];
    char *argv[1];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND(1)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_var_key(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len, int min_argc, int has_timeout)
{
    long timeout;
	int argc = ZEND_NUM_ARGS();
    if(argc < min_argc) {
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(argc == 0 || zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS
	zend_bool single_array = 0;
    if(has_timeout == 0) {
        single_array = argc==1 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0])==IS_ARRAY;
    } else {
        single_array = argc==2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0])==IS_ARRAY &&
            SW_REDIS_COMMAND_ARGS_TYPE(z_args[1])==IS_LONG;
        timeout = SW_REDIS_COMMAND_ARGS_LVAL(z_args[1]);
    }
	if (single_array)
	{
		argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 1;
	}
	else
	{
		argc++;
	}

	SW_REDIS_COMMAND_ALLOC_ARGV
	int i = 0;
	SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
	char buf[32];
	size_t buf_len;
	if (single_array)
	{
		zval *value;
		SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
#if PHP_MAJOR_VERSION < 7
			convert_to_string(value);
			SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
		SW_HASHTABLE_FOREACH_END();
        if(has_timeout) {
			buf_len = snprintf(buf, sizeof(buf), "%ld", timeout);
			SW_REDIS_COMMAND_ARGV_FILL((char*)buf, buf_len);
        }
	}
	else
	{
        if(has_timeout && SW_REDIS_COMMAND_ARGS_TYPE(z_args[argc-2]) != IS_LONG) {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "Timeout value must be a LONG" TSRMLS_CC);
            efree(z_args);
			RETURN_FALSE;
        }
		int j, tail;
		tail = has_timeout ? argc - 2 : argc - 1;
		for (j = 0; j < tail; ++j)
		{
#if PHP_MAJOR_VERSION < 7
            convert_to_string(z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
		}
        if(has_timeout) {
			buf_len = snprintf(buf, sizeof(buf), "%ld", SW_REDIS_COMMAND_ARGS_LVAL(z_args[tail]));
			SW_REDIS_COMMAND_ARGV_FILL((char*)buf, buf_len);
        }
	}
    efree(z_args);

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}


static sw_inline void sw_redis_command_key(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key;
    zend_size_t key_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[2];
    char *argv[2];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND(2)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
    int argc = ZEND_NUM_ARGS();

    // We at least need a key and one value
    if(argc < 2) {
        RETURN_FALSE;
    }

    // Make sure we at least have a key, and we can get other args
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
		RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS

    int i = 0, j;
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
#if PHP_MAJOR_VERSION < 7
    convert_to_string(z_args[0]);
    SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
#else
    zend_string *convert_str = zval_get_string(&z_args[0]);
    SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
    zend_string_release(convert_str);
#endif
	for (j = 1; j < argc - 1; ++j)
	{
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(SW_REDIS_COMMAND_ARGS_REF(z_args[j]))
	}
	efree(z_args);
    SW_REDIS_COMMAND(argc);
	SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
    char *key;
	zend_size_t key_len;
	long l_val;
    zval *z_value;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &key, &key_len, &l_val, &z_value) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    SW_REDIS_COMMAND(4);
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_long_str(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key, *val;
    zend_size_t key_len, val_len;
    long l_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &key, &key_len, &l_val, &val, &val_len)==FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL(val, val_len)
    SW_REDIS_COMMAND(4);
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_long(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key;
    zend_size_t key_len;
    long l_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &key, &key_len, &l_val)==FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND(3);
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key;
    zend_size_t key_len;
    long l1_val, l2_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll", &key, &key_len, &l1_val, &l2_val)==FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l1_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    sprintf(str, "%ld", l2_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND(4);
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_dbl(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key;
    zend_size_t key_len;
    double d_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sd", &key, &key_len, &d_val) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%f", d_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND(3)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_key(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key1, *key2;
    zend_size_t key1_len, key2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key1, &key1_len, &key2, &key2_len) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
    SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
    SW_REDIS_COMMAND(3)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_val(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key;
    zend_size_t key_len;
    zval *z_value;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &key, &key_len, &z_value) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    SW_REDIS_COMMAND(3)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_str(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key, *val;
    zend_size_t key_len, val_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &val, &val_len) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(val, val_len)
    SW_REDIS_COMMAND(3)
    SW_REDIS_COMMAND_YIELD
}

static sw_inline void sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAMETERS, char *cmd, int cmd_len)
{
	char *key, *val1, *val2;
    zend_size_t key_len, val1_len, val2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &key, &key_len, &val1, &val1_len, &val2, &val2_len) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i =0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(val1, val1_len)
    SW_REDIS_COMMAND_ARGV_FILL(val2, val2_len)
    SW_REDIS_COMMAND(4)
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, __construct);
static PHP_METHOD(swoole_redis_coro, __destruct);
static PHP_METHOD(swoole_redis_coro, connect);
static PHP_METHOD(swoole_redis_coro, setDefer);
static PHP_METHOD(swoole_redis_coro, getDefer);
static PHP_METHOD(swoole_redis_coro, recv);
static PHP_METHOD(swoole_redis_coro, request);
static PHP_METHOD(swoole_redis_coro, close);
/*---------------------Redis Command------------------------*/
static PHP_METHOD(swoole_redis_coro, set);
static PHP_METHOD(swoole_redis_coro, setBit);
static PHP_METHOD(swoole_redis_coro, setEx);
static PHP_METHOD(swoole_redis_coro, psetEx);
static PHP_METHOD(swoole_redis_coro, lSet);
static PHP_METHOD(swoole_redis_coro, get);
static PHP_METHOD(swoole_redis_coro, mGet);
static PHP_METHOD(swoole_redis_coro, del);
static PHP_METHOD(swoole_redis_coro, hDel);
static PHP_METHOD(swoole_redis_coro, hSet);
static PHP_METHOD(swoole_redis_coro, hMSet);
static PHP_METHOD(swoole_redis_coro, hSetNx);
static PHP_METHOD(swoole_redis_coro, mSet);
static PHP_METHOD(swoole_redis_coro, mSetNx);
static PHP_METHOD(swoole_redis_coro, getKeys);
static PHP_METHOD(swoole_redis_coro, exists);
static PHP_METHOD(swoole_redis_coro, type);
static PHP_METHOD(swoole_redis_coro, strLen);
static PHP_METHOD(swoole_redis_coro, lPop);
static PHP_METHOD(swoole_redis_coro, blPop);
static PHP_METHOD(swoole_redis_coro, rPop);
static PHP_METHOD(swoole_redis_coro, brPop);
static PHP_METHOD(swoole_redis_coro, bRPopLPush);
static PHP_METHOD(swoole_redis_coro, lSize);
static PHP_METHOD(swoole_redis_coro, sSize);
static PHP_METHOD(swoole_redis_coro, sPop);
static PHP_METHOD(swoole_redis_coro, sMembers);
static PHP_METHOD(swoole_redis_coro, sRandMember);
static PHP_METHOD(swoole_redis_coro, persist);
static PHP_METHOD(swoole_redis_coro, ttl);
static PHP_METHOD(swoole_redis_coro, pttl);
static PHP_METHOD(swoole_redis_coro, zCard);
static PHP_METHOD(swoole_redis_coro, hLen);
static PHP_METHOD(swoole_redis_coro, hKeys);
static PHP_METHOD(swoole_redis_coro, hVals);
static PHP_METHOD(swoole_redis_coro, hGetAll);
static PHP_METHOD(swoole_redis_coro, restore);
static PHP_METHOD(swoole_redis_coro, dump);
static PHP_METHOD(swoole_redis_coro, debug);
static PHP_METHOD(swoole_redis_coro, renameKey);
static PHP_METHOD(swoole_redis_coro, renameNx);
static PHP_METHOD(swoole_redis_coro, rpoplpush);
static PHP_METHOD(swoole_redis_coro, randomKey);
static PHP_METHOD(swoole_redis_coro, ping);
static PHP_METHOD(swoole_redis_coro, auth);
static PHP_METHOD(swoole_redis_coro, unwatch);
static PHP_METHOD(swoole_redis_coro, watch);
static PHP_METHOD(swoole_redis_coro, save);
static PHP_METHOD(swoole_redis_coro, bgSave);
static PHP_METHOD(swoole_redis_coro, lastSave);
static PHP_METHOD(swoole_redis_coro, flushDB);
static PHP_METHOD(swoole_redis_coro, flushAll);
static PHP_METHOD(swoole_redis_coro, dbSize);
static PHP_METHOD(swoole_redis_coro, bgrewriteaof);
static PHP_METHOD(swoole_redis_coro, time);
static PHP_METHOD(swoole_redis_coro, role);
static PHP_METHOD(swoole_redis_coro, setRange);
static PHP_METHOD(swoole_redis_coro, setNx);
static PHP_METHOD(swoole_redis_coro, getSet);
static PHP_METHOD(swoole_redis_coro, append);
static PHP_METHOD(swoole_redis_coro, lPushx);
static PHP_METHOD(swoole_redis_coro, lPush);
static PHP_METHOD(swoole_redis_coro, rPush);
static PHP_METHOD(swoole_redis_coro, rPushx);
static PHP_METHOD(swoole_redis_coro, sContains);
static PHP_METHOD(swoole_redis_coro, zScore);
static PHP_METHOD(swoole_redis_coro, zRank);
static PHP_METHOD(swoole_redis_coro, zRevRank);
static PHP_METHOD(swoole_redis_coro, hGet);
static PHP_METHOD(swoole_redis_coro, hMGet);
static PHP_METHOD(swoole_redis_coro, hExists);
static PHP_METHOD(swoole_redis_coro, publish);
static PHP_METHOD(swoole_redis_coro, zIncrBy);
static PHP_METHOD(swoole_redis_coro, zAdd);
static PHP_METHOD(swoole_redis_coro, zDeleteRangeByScore);
static PHP_METHOD(swoole_redis_coro, zCount);
static PHP_METHOD(swoole_redis_coro, zRange);
static PHP_METHOD(swoole_redis_coro, zRevRange);
static PHP_METHOD(swoole_redis_coro, zRangeByScore);
static PHP_METHOD(swoole_redis_coro, zRevRangeByScore);
static PHP_METHOD(swoole_redis_coro, zRangeByLex);
static PHP_METHOD(swoole_redis_coro, zRevRangeByLex);
static PHP_METHOD(swoole_redis_coro, zInter);
static PHP_METHOD(swoole_redis_coro, zUnion);
static PHP_METHOD(swoole_redis_coro, incrBy);
static PHP_METHOD(swoole_redis_coro, hIncrBy);
static PHP_METHOD(swoole_redis_coro, incr);
static PHP_METHOD(swoole_redis_coro, decrBy);
static PHP_METHOD(swoole_redis_coro, decr);
static PHP_METHOD(swoole_redis_coro, getBit);
static PHP_METHOD(swoole_redis_coro, lGet);
static PHP_METHOD(swoole_redis_coro, lInsert);
static PHP_METHOD(swoole_redis_coro, setTimeout);
static PHP_METHOD(swoole_redis_coro, pexpire);
static PHP_METHOD(swoole_redis_coro, expireAt);
static PHP_METHOD(swoole_redis_coro, pexpireAt);
static PHP_METHOD(swoole_redis_coro, move);
static PHP_METHOD(swoole_redis_coro, select);
static PHP_METHOD(swoole_redis_coro, getRange);
static PHP_METHOD(swoole_redis_coro, listTrim);
static PHP_METHOD(swoole_redis_coro, lGetRange);
static PHP_METHOD(swoole_redis_coro, lRem);
static PHP_METHOD(swoole_redis_coro, zDeleteRangeByRank);
static PHP_METHOD(swoole_redis_coro, incrByFloat);
static PHP_METHOD(swoole_redis_coro, hIncrByFloat);
static PHP_METHOD(swoole_redis_coro, bitCount);
static PHP_METHOD(swoole_redis_coro, bitOp);
static PHP_METHOD(swoole_redis_coro, sAdd);
static PHP_METHOD(swoole_redis_coro, sMove);
static PHP_METHOD(swoole_redis_coro, sDiff);
static PHP_METHOD(swoole_redis_coro, sDiffStore);
static PHP_METHOD(swoole_redis_coro, sUnion);
static PHP_METHOD(swoole_redis_coro, sUnionStore);
static PHP_METHOD(swoole_redis_coro, sInter);
static PHP_METHOD(swoole_redis_coro, sInterStore);
static PHP_METHOD(swoole_redis_coro, sRemove);
static PHP_METHOD(swoole_redis_coro, zDelete);
static PHP_METHOD(swoole_redis_coro, subscribe);
static PHP_METHOD(swoole_redis_coro, pSubscribe);
static PHP_METHOD(swoole_redis_coro, multi);
static PHP_METHOD(swoole_redis_coro, exec);
static PHP_METHOD(swoole_redis_coro, eval);
static PHP_METHOD(swoole_redis_coro, evalSha);
static PHP_METHOD(swoole_redis_coro, script);
/*---------------------Redis Command End------------------------*/

static const zend_function_entry swoole_redis_coro_methods[] =
{
    PHP_ME(swoole_redis_coro, __construct, arginfo_swoole_redis_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_redis_coro, __destruct, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_redis_coro, connect, arginfo_swoole_redis_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setDefer, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getDefer, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, recv, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, request, arginfo_swoole_redis_coro_request, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, close, NULL, ZEND_ACC_PUBLIC)
    /*---------------------Redis Command------------------------*/
    PHP_ME(swoole_redis_coro, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setBit, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setEx, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, psetEx, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lSet, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, get, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mGet, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, del, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hDel, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hSet, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hMSet, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hSetNx, NULL, ZEND_ACC_PUBLIC)
	PHP_MALIAS(swoole_redis_coro, delete, del, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mSet, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mSetNx, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getKeys, NULL, ZEND_ACC_PUBLIC)
	PHP_MALIAS(swoole_redis_coro, keys, getKeys, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, exists, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, type, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, strLen, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lPop, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, blPop, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rPop, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, brPop, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bRPopLPush, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lSize, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lLen, lSize, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sSize, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, scard, sSize, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sPop, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sMembers, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, sGetMembers, sMembers, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sRandMember, arginfo_swoole_redis_coro_key_opt_long, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, persist, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, ttl, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pttl, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zCard, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zSize, zCard, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hLen, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hKeys, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hVals, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hGetAll, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, debug, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, restore, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, dump, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, renameKey, NULL, ZEND_ACC_PUBLIC)
	PHP_MALIAS(swoole_redis_coro, rename, renameKey, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, renameNx, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rpoplpush, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, randomKey, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, ping, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, auth, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, unwatch, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, watch, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, save, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, bgSave, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lastSave, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, flushDB, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, flushAll, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, dbSize, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, bgrewriteaof, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, time, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, role, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setRange, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, setNx, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, getSet, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, append, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lPushx, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lPush, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, rPush, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, rPushx, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sContains, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, sismember, sContains, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zScore, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRank, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRevRank, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, hGet, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, hMGet, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, hExists, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, publish, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zIncrBy, arginfo_swoole_redis_coro_zIncrBy, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zAdd, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zDeleteRangeByScore, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemRangeByScore, zDeleteRangeByScore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zCount, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRange, arginfo_swoole_redis_coro_zRange, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRevRange, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRangeByScore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRevRangeByScore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRangeByLex, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zRevRangeByLex, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zInter, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zinterstore, zInter, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zUnion, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zunionstore, zUnion, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, incrBy, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, hIncrBy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, incr, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, decrBy, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, decr, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, getBit, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lInsert, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lGet, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_MALIAS(swoole_redis_coro, lIndex, lGet, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, setTimeout, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, expire, setTimeout, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, pexpire, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, expireAt, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, pexpireAt, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, move, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, select, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, getRange, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, listTrim, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, ltrim, listTrim, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lGetRange, NULL, ZEND_ACC_PUBLIC)
	PHP_MALIAS(swoole_redis_coro, lRange, lGetRange, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, lRem, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lRemove,lRem, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zDeleteRangeByRank, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemRangeByRank, zDeleteRangeByRank, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, incrByFloat, arginfo_swoole_redis_coro_incrByFloat, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, hIncrByFloat, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, bitCount, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, bitOp, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sAdd, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sMove, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sDiff, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sDiffStore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sUnion, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sUnionStore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sInter, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sInterStore, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, sRemove, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, srem, sRemove, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, zDelete, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemove, zDelete, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRem, zDelete, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_redis_coro, pSubscribe, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, subscribe, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, multi, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, exec, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, eval, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, evalSha, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, script, NULL, ZEND_ACC_PUBLIC)
    /*---------------------Redis Command End------------------------*/
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
    PHP_FE_END
};

void swoole_redis_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_redis_coro_ce, "Swoole\\Coroutine\\Redis", swoole_redis_coro_methods);
    swoole_redis_coro_class_entry_ptr = zend_register_internal_class(&swoole_redis_coro_ce TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Redis", swoole_redis_coro_class_entry_ptr);
    }

    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("host"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("port"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("sock"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_redis_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_redis_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_redis_coro_class_entry_ptr, SW_STRL("errMsg")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);

	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_MULTI", SW_REDIS_MODE_MULTI, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_PIPELINE", SW_REDIS_MODE_PIPELINE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_NOT_FOUND", SW_REDIS_NOT_FOUND, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_STRING", SW_REDIS_STRING, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_SET", SW_REDIS_SET, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_LIST", SW_REDIS_LIST, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_ZSET", SW_REDIS_ZSET, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_HASH", SW_REDIS_HASH, CONST_CS | CONST_PERSISTENT);
}

static void redis_coro_close(void* data)
{
    redisAsyncContext *context = data;
    redisAsyncDisconnect(context);
}

static void redis_coro_free(void* redis)
{
    efree(redis);
}

static swRedisClient* redis_coro_create(zval *object)
{
    swRedisClient *redis = emalloc(sizeof(swRedisClient));
    bzero(redis, sizeof(swRedisClient));

    redis->object = object;
    sw_copy_to_stack(redis->object, redis->_object);

    swoole_set_object(object, redis);

    redis->state = SWOOLE_REDIS_CORO_STATE_CONNECT;
    redis->iowait = SW_REDIS_CORO_STATUS_READY;
    redis->pipeline_result = NULL;
    redis->timeout = SW_REDIS_CONNECT_TIMEOUT;

    return redis;
}

static PHP_METHOD(swoole_redis_coro, __construct)
{
    zval *zset = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|z", &zset) == FAILURE)
    {
        return;
    }

    swRedisClient *redis = redis_coro_create(getThis());

    if (zset && !ZVAL_IS_NULL(zset))
    {
        php_swoole_array_separate(zset);
        zend_update_property(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
        sw_zval_ptr_dtor(&zset);

        HashTable *vht;
        zval *ztmp;
        vht = Z_ARRVAL_P(zset);
        /**
         * timeout
         */
        if (php_swoole_array_get_value(vht, "timeout", ztmp))
        {
            convert_to_double(ztmp);
            redis->timeout = (double) Z_DVAL_P(ztmp);
        }
    }
}

static PHP_METHOD(swoole_redis_coro, connect)
{
    char *host;
    zend_size_t host_len;
    long port;
	zend_bool serialize = 0;

    coro_check(TSRMLS_C);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|b", &host, &host_len, &port, &serialize) == FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "host is empty." TSRMLS_CC);
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis)
    {
        redis = redis_coro_create(getThis());
    }

	redis->serialize = serialize;
    redisAsyncContext *context;

    if (redis->connected)
    {
        swoole_php_fatal_error(E_WARNING, "connection to the server has already been established.");
        RETURN_FALSE;
    }

    if (strncasecmp(host, ZEND_STRL("unix:/")) == 0)
    {
        context = redisAsyncConnectUnix(host + 5);
    }
    else
    {
        if (port <= 1 || port > 65535)
        {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "port is invalid." TSRMLS_CC);
			RETURN_FALSE;
        }
        context = redisAsyncConnect(host, (int) port);
    }

    if (context->err)
    {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), context->err TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), context->errstr TSRMLS_CC);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_READ, swoole_redis_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE, swoole_redis_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_ERROR, swoole_redis_coro_onError);
    }

    redisAsyncSetConnectCallback(context, swoole_redis_coro_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_coro_onClose);

    zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("sock"), context->c.fd TSRMLS_CC);

    redis->context = context;
    context->ev.addRead = swoole_redis_coro_event_AddRead;
    context->ev.delRead = swoole_redis_coro_event_DelRead;
    context->ev.addWrite = swoole_redis_coro_event_AddWrite;
    context->ev.delWrite = swoole_redis_coro_event_DelWrite;
    context->ev.cleanup = swoole_redis_coro_event_Cleanup;
    context->ev.data = redis;

    zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host TSRMLS_CC);
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, redis->context->c.fd, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_event_add failed. Erorr: %s[%d].", redis->context->errstr, redis->context->err);
        RETURN_FALSE;
    }

    swConnection *conn = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    conn->object = redis;

	php_context *sw_current_context = swoole_get_property(getThis(), 0);
	if (!sw_current_context)
	{
		sw_current_context = emalloc(sizeof(php_context));
		swoole_set_property(getThis(), 0, sw_current_context);
	}
	sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
	sw_current_context->onTimeout = NULL;
#if PHP_MAJOR_VERSION < 7
	sw_current_context->coro_params = getThis();
#else
	sw_current_context->coro_params = *getThis();
#endif
    if (redis->timeout > 0)
    {
        php_swoole_check_timer((int) (redis->timeout * 1000));
        redis->timer = SwooleG.timer.add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
    }
	coro_save(sw_current_context);
	coro_yield();
}

static PHP_METHOD(swoole_redis_coro, getDefer)
{
    swRedisClient *redis = swoole_get_object(getThis());

	RETURN_BOOL(redis->defer);
}

static PHP_METHOD(swoole_redis_coro, setDefer)
{
	zend_bool defer = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &defer) == FAILURE)
    {
        return;
    }

    swRedisClient *redis = swoole_get_object(getThis());
	if (redis->iowait > SW_REDIS_CORO_STATUS_READY)
	{
		RETURN_BOOL(defer);
	}

	redis->defer = defer;

	RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_coro, recv)
{
    swRedisClient *redis = swoole_get_object(getThis());

	if (!redis->defer)
	{
        swoole_php_fatal_error(E_WARNING, "you should not use recv without defer.");
		RETURN_FALSE;
	}

    if (redis->iowait == SW_REDIS_CORO_STATUS_DONE)
    {
        redis->iowait = SW_REDIS_CORO_STATUS_READY;
        zval *result = redis->defer_result;
        RETVAL_ZVAL(result, 0, 0);
        efree(result);
        redis->defer_result = NULL;
        return;
    }

    if (redis->iowait != SW_REDIS_CORO_STATUS_WAIT)
    {
        swoole_php_fatal_error(E_WARNING, "no request.");
        RETURN_FALSE;
    }

	redis->cid = get_current_cid();
	redis->defer_yield = 1;
	php_context *sw_current_context = swoole_get_property(getThis(), 0);
	coro_save(sw_current_context);
	coro_yield();
}

static PHP_METHOD(swoole_redis_coro, close)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis || !redis->context)
    {
        RETURN_FALSE;
    }
    if (redis->timer)
    {
        swTimer_del(&SwooleG.timer, redis->timer);
        redis->timer = NULL;
    }
	if (redis->state == SWOOLE_REDIS_CORO_STATE_CLOSED)
	{
		RETURN_TRUE;
	}
    if (unlikely(redis->cid && redis->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "redis client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, redis->context->c.fd);
    _socket->active = 0;

    redis->connected = 0;
	redis->state = SWOOLE_REDIS_CORO_STATE_CLOSING;
	redis->iowait = SW_REDIS_CORO_STATUS_CLOSED;
    redisCallback *head = redis->context->replies.head;
    redisCallback *cb = head;
    while (head != NULL)
    {
        head = cb->next;
        free(cb);
        cb = head;
    }

    redis->object = NULL;
    redis->released = 1;
    redis->context->replies.head = NULL;
    if (redis->connecting)
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, redis_coro_close, redis->context);
    }
    else
    {
        redis_coro_close(redis->context);
    }

    zend_update_property_bool(swoole_redis_coro_class_entry_ptr, getThis(), SW_STRL("connected") - 1, 0);
    swoole_set_object(getThis(), NULL);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_coro, __destruct)
{
    swTraceLog(SW_TRACE_REDIS_CLIENT, "object_id=%d", sw_get_object_handle(getThis()));

	php_context *sw_current_context = swoole_get_property(getThis(), 0);
	if (sw_current_context)
	{
		efree(sw_current_context);
		swoole_set_property(getThis(), 0, NULL);
	}

    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis)
    {
        return;
    }
    if (redis->state != SWOOLE_REDIS_CORO_STATE_CLOSED)
    {
        swTraceLog(SW_TRACE_REDIS_CLIENT, "close connection, fd=%d", redis->context->c.fd);

        zval *retval = NULL;
        zval *zobject = getThis();
        sw_zend_call_method_with_0_params(&zobject, swoole_redis_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    else if (!redis->released)
    {
        swoole_set_object(getThis(), NULL);
        efree(redis);
    }
}

static PHP_METHOD(swoole_redis_coro, set)
{
    char *key, *exp_type = NULL, *set_type = NULL;
	zend_size_t key_len, argc = 3;
	zval *z_value, *z_opts = NULL;
    long expire = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|z", &key, &key_len, &z_value, &z_opts) == FAILURE)
	{
		return;
	}

	SW_REDIS_COMMAND_CHECK

    if (z_opts && Z_TYPE_P(z_opts) != IS_LONG && Z_TYPE_P(z_opts) != IS_ARRAY
       && Z_TYPE_P(z_opts) != IS_NULL)
    {
        RETURN_FALSE;
    }

    if (z_opts && Z_TYPE_P(z_opts) == IS_ARRAY) {
        HashTable *kt = Z_ARRVAL_P(z_opts);

#if PHP_MAJOR_VERSION >= 7
        zend_string *zkey;
        zend_ulong idx;
        zval *v;

        /* Iterate our option array */
        ZEND_HASH_FOREACH_KEY_VAL(kt, idx, zkey, v) {
            /* Detect PX or EX argument and validate timeout */
            if (zkey && IS_EX_PX_ARG(zkey->val)) {
                /* Set expire type */
                exp_type = zkey->val;

                /* Try to extract timeout */
                if (Z_TYPE_P(v) == IS_LONG) {
                    expire = Z_LVAL_P(v);
                } else if (Z_TYPE_P(v) == IS_STRING) {
                    expire = atol(Z_STRVAL_P(v));
                }

                /* Expiry can't be set < 1 */
                if (expire < 1) RETURN_FALSE;
                argc += 2;
            } else if (Z_TYPE_P(v) == IS_STRING && IS_NX_XX_ARG(Z_STRVAL_P(v))) {
                argc += 1;
                set_type = Z_STRVAL_P(v);
            }
            (void) idx;
        } ZEND_HASH_FOREACH_END();
#else
        int type;
        unsigned int ht_key_len;
        unsigned long idx;
        char *k;
        zval **v;

        /* Iterate our option array */
        for(zend_hash_internal_pointer_reset(kt);
            zend_hash_has_more_elements(kt) == SUCCESS;
            zend_hash_move_forward(kt))
        {
            // Grab key and value
            type = zend_hash_get_current_key_ex(kt, &k, &ht_key_len, &idx, 0, NULL);
            zend_hash_get_current_data(kt, (void**)&v);

            /* Detect PX or EX argument and validate timeout */
            if (type == HASH_KEY_IS_STRING && IS_EX_PX_ARG(k)) {
                /* Set expire type */
                exp_type = k;

                /* Try to extract timeout */
                if (Z_TYPE_PP(v) == IS_LONG) {
                    expire = Z_LVAL_PP(v);
                } else if (Z_TYPE_PP(v) == IS_STRING) {
                    expire = atol(Z_STRVAL_PP(v));
                }

                /* Expiry can't be set < 1 */
                if (expire < 1) RETURN_FALSE;
                argc += 2;
            } else if (Z_TYPE_PP(v) == IS_STRING && IS_NX_XX_ARG(Z_STRVAL_PP(v))) {
                argc += 1;
                set_type = Z_STRVAL_PP(v);
            }
            (void) idx;
        }
#endif
    } else if(z_opts && Z_TYPE_P(z_opts) == IS_LONG) {
        /* Grab expiry and fail if it's < 1 */
        expire = Z_LVAL_P(z_opts);
        if (expire < 1) RETURN_FALSE;
		argc += 1;
    }

	SW_REDIS_COMMAND_ALLOC_ARGV

	int i = 0;
	if (exp_type || set_type)
	{
		SW_REDIS_COMMAND_ARGV_FILL("SET", 3)
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)

		if (set_type)
		{
			SW_REDIS_COMMAND_ARGV_FILL(set_type, (size_t) strlen(set_type))
		}

		if (exp_type)
		{
			SW_REDIS_COMMAND_ARGV_FILL(exp_type, (size_t) strlen(exp_type))

			char str[32];
			sprintf(str, "%ld", expire);
			SW_REDIS_COMMAND_ARGV_FILL(str, (size_t) strlen(str))
		}
	} else if (expire > 0) {
		SW_REDIS_COMMAND_ARGV_FILL("SETEX", 5)
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

		char str[32];
		sprintf(str, "%ld", expire);
		SW_REDIS_COMMAND_ARGV_FILL(str, (size_t) strlen(str))

		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
	} else {
		SW_REDIS_COMMAND_ARGV_FILL("SET", 3)
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
	}

	SW_REDIS_COMMAND(argc)

	SW_REDIS_COMMAND_FREE_ARGV

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, setBit)
{
    char *key;
    zend_size_t key_len;
    long offset;
    zend_bool val;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slb", &key, &key_len,
                             &offset, &val)==FAILURE)
    {
        return;
    }

    // Validate our offset
    if(offset < SW_BITOP_MIN_OFFSET || offset >SW_BITOP_MAX_OFFSET) {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid OFFSET for bitop command (must be between 0-2^32-1)" TSRMLS_CC);
		RETURN_FALSE;
    }

	SW_REDIS_COMMAND_CHECK

	int i = 0;
    size_t argvlen[4];
    char *argv[4];

	SW_REDIS_COMMAND_ARGV_FILL("SETBIT", 6)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

	char str[32];
	sprintf(str, "%ld", offset);
	SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))

	SW_REDIS_COMMAND_ARGV_FILL(val ? "1" : "0", 1)

	SW_REDIS_COMMAND(4);

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, setEx)
{
	sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SETEX", 5);
}

static PHP_METHOD(swoole_redis_coro, psetEx)
{
	sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PSETEX", 6);
}

static PHP_METHOD(swoole_redis_coro, lSet)
{
	sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LSET", 4);
}

static PHP_METHOD(swoole_redis_coro, restore)
{
	sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RESTORE", 7);
}

static PHP_METHOD(swoole_redis_coro, dump)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DUMP", 4);
}

static PHP_METHOD(swoole_redis_coro, debug)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DEBUG", 5);
}

static PHP_METHOD(swoole_redis_coro, get)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "GET", 3);
}

static PHP_METHOD(swoole_redis_coro, mGet)
{
    zval *z_args;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "a", &z_args) == FAILURE)
    {
        return;
    }
	int argc;
	argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
	if (argc == 0)
	{
		RETURN_FALSE;
	}
	SW_REDIS_COMMAND_CHECK
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
	int i = 0;
	zval *value;
	SW_REDIS_COMMAND_ARGV_FILL("MGET", 4)
	SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(z_args), value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hSet)
{
    char *key, *field;
    zend_size_t key_len, field_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &key, &key_len,
                             &field, &field_len, &z_val) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK
	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("HSET", 4)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(field, field_len)
	SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hMSet)
{
    char *key;
    zend_size_t key_len, argc;
    zval *z_arr;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &key_len,
                             &z_arr)==FAILURE)
    {
        return;
    }
    if((argc = zend_hash_num_elements(Z_ARRVAL_P(z_arr))) == 0) {
		RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK
	int i = 0;
	argc = argc * 2 + 2;
	zval *value;
	char buf[32];
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("HMSET", 5)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
#if  (PHP_MAJOR_VERSION < 7)
	int keytype;
	SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(z_arr), key, key_len, keytype, value)
	{
		if (HASH_KEY_IS_STRING != keytype)
		{
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
		}
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
	}
	SW_HASHTABLE_FOREACH_END();
#else
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_arr), idx, _key, value) {
        if (_key == NULL) {
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    } ZEND_HASH_FOREACH_END();
#endif

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hSetNx)
{
    char *key, *field;
    zend_size_t key_len, field_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &key, &key_len,
                             &field, &field_len, &z_val) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK
	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("HSETNX", 6)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(field, field_len)
	SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_val), Z_STRLEN_P(z_val))

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hDel)
{
	int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(argc < 2 || zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS
	argc++;
	int i = 0, j;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("HDEL", 4)
	for (j = 0; j < argc-1; ++j)
	{
#if PHP_MAJOR_VERSION < 7
        convert_to_string(z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	}
    efree(z_args);
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, watch)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "WATCH", 5, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, del)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DEL", 3, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sDiff)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SDIFF", 5, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sDiffStore)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SDIFFSTORE", 10, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sUnion)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SUNION", 6, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sUnionStore)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SUNIONSTORE", 11, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sInter)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SINTER", 6, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sInterStore)
{
	sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SINTERSTORE", 11, 1, 0);
}

static PHP_METHOD(swoole_redis_coro, mSet)
{
	zval *z_args;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &z_args) == FAILURE)
    {
        return;
    }
	int argc;
	argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
	if (argc == 0)
	{
		RETURN_FALSE;
	}
	SW_REDIS_COMMAND_CHECK
	argc *= 2;
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
	int i = 0;
	SW_REDIS_COMMAND_ARGV_FILL("MSET", 4)
	zval *value;
	char buf[32];
    char *key;
    uint32_t key_len;
#if  (PHP_MAJOR_VERSION < 7)
	int keytype;
	SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(z_args), key, key_len, keytype, value)
	{
		if (HASH_KEY_IS_STRING != keytype)
		{
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
		}
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
	}
	SW_HASHTABLE_FOREACH_END();
#else
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_args), idx, _key, value) {
        if (_key == NULL) {
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    } ZEND_HASH_FOREACH_END();
#endif

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, mSetNx)
{
	zval *z_args;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &z_args)==FAILURE)
    {
        return;
    }
	int argc;
	argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
	if (argc == 0)
	{
		RETURN_FALSE;
	}
	SW_REDIS_COMMAND_CHECK
	argc *= 2;
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
	int i = 0;
	SW_REDIS_COMMAND_ARGV_FILL("MSETNX", 6)
	zval *value;
	char buf[32];
    char *key;
    uint32_t key_len;
#if  (PHP_MAJOR_VERSION < 7)
	int keytype;
	SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(z_args), key, key_len, keytype, value)
	{
		if (HASH_KEY_IS_STRING != keytype)
		{
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
		}
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
	}
	SW_HASHTABLE_FOREACH_END();
#else
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_args), idx, _key, value) {
        if (_key == NULL) {
			key_len = snprintf(buf, sizeof(buf), "%ld", (long)idx);
			key = (char*)buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
		SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    } ZEND_HASH_FOREACH_END();
#endif

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, getKeys)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "KEYS", 4);
}

static PHP_METHOD(swoole_redis_coro, exists)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "EXISTS", 6);
}

static PHP_METHOD(swoole_redis_coro, type)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "TYPE", 4);
}

static PHP_METHOD(swoole_redis_coro, strLen)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "STRLEN", 6);
}

static PHP_METHOD(swoole_redis_coro, lPop)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LPOP", 4);
}

static PHP_METHOD(swoole_redis_coro, bRPopLPush)
{
    char *key1, *key2;
    zend_size_t key1_len, key2_len;
    long timeout;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl", &key1, &key1_len,
                             &key2, &key2_len, &timeout) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK
	int argc, i = 0;
	argc = timeout < 0 ? 3 : 4;
	SW_REDIS_COMMAND_ALLOC_ARGV
	if (timeout < 0)
	{
		SW_REDIS_COMMAND_ARGV_FILL("RPOPLPUSH", 9)
		SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
		SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
	}
	else
	{
		SW_REDIS_COMMAND_ARGV_FILL("BRPOPLPUSH", 10)
		SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
		SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
		char str[32];
		sprintf(str, "%ld", timeout);
		SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
	}

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, blPop)
{
    int argc = ZEND_NUM_ARGS();

    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1)
    {
        efree(z_args);
        return;
    }
	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS

	zend_bool single_array = 0;
	if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY)
	{
		argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
		single_array = 1;
	}
	else
	{
		argc += 1;
	}
	int i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("BLPOP", 5)
	if (single_array)
	{
		zval *value;
		SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
#if PHP_MAJOR_VERSION < 7
			convert_to_string(value);
			SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
		SW_HASHTABLE_FOREACH_END();
#if PHP_MAJOR_VERSION < 7
		convert_to_string(z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[1]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[1]))
#else
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	}
	else
	{
		int j;
		for (j = 0; j < argc - 1; ++j)
		{
#if PHP_MAJOR_VERSION < 7
			convert_to_string(z_args[j]);
			SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
		}
	}
	efree(z_args);

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, brPop)
{
    int argc = ZEND_NUM_ARGS();

    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1)
    {
        efree(z_args);
        return;
    }
	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS

	zend_bool single_array = 0;
	if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY)
	{
		argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
		single_array = 1;
	}
	else
	{
		argc += 1;
	}
	int i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("BRPOP", 5)
	if (single_array)
	{
		zval *value;
		SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
#if PHP_MAJOR_VERSION < 7
            convert_to_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
        SW_HASHTABLE_FOREACH_END();
#if PHP_MAJOR_VERSION < 7
        convert_to_string(z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[1]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[1]))
#else
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	}
	else
	{
		int j;
		for (j = 0; j < argc - 1; ++j)
		{
#if PHP_MAJOR_VERSION < 7
            convert_to_string(z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
#endif
		}
	}
    efree(z_args);

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, rPop)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RPOP", 4);
}

static PHP_METHOD(swoole_redis_coro, lSize)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LLEN", 4);
}

static PHP_METHOD(swoole_redis_coro, sSize)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SCARD", 5);
}

static PHP_METHOD(swoole_redis_coro, sPop)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SPOP", 4);
}

static PHP_METHOD(swoole_redis_coro, sMembers)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SMEMBERS", 8);
}

static PHP_METHOD(swoole_redis_coro, sRandMember)
{
    char *key;
    zend_size_t key_len;
    long count;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &key, &key_len,
                             &count) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0, argc, buf_len;
	char buf[32];
	argc = ZEND_NUM_ARGS() == 2 ? 3 : 2;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("SRANDMEMBER", 11);
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len);
	if (argc == 3)
	{
		buf_len = snprintf(buf, sizeof(buf), "%ld", count);
		SW_REDIS_COMMAND_ARGV_FILL((char *)buf, buf_len);
	}
	SW_REDIS_COMMAND(argc);
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, persist)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PERSIST", 7);
}

static PHP_METHOD(swoole_redis_coro, ttl)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "TTL", 3);
}

static PHP_METHOD(swoole_redis_coro, pttl)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PTTL", 4);
}

static PHP_METHOD(swoole_redis_coro, zCard)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZCARD", 5);
}

static PHP_METHOD(swoole_redis_coro, hLen)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HLEN", 4);
}

static PHP_METHOD(swoole_redis_coro, hKeys)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HKEYS", 5);
}

static PHP_METHOD(swoole_redis_coro, hVals)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HVALS", 5);
}

static PHP_METHOD(swoole_redis_coro, hGetAll)
{
	sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HGETALL", 7);
}

static PHP_METHOD(swoole_redis_coro, renameKey)
{
	sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RENAME", 6);
}

static PHP_METHOD(swoole_redis_coro, renameNx)
{
	sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RENAMENX", 8);
}

static PHP_METHOD(swoole_redis_coro, rpoplpush)
{
	sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RPOPLPUSH", 9);
}

static PHP_METHOD(swoole_redis_coro, randomKey)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RANDOMKEY", 9);
}

static PHP_METHOD(swoole_redis_coro, unwatch)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "UNWATCH", 7);
}

static PHP_METHOD(swoole_redis_coro, ping)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PING", 4);
}

static PHP_METHOD(swoole_redis_coro, auth)
{
	char *pw;
    zend_size_t pw_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pw, &pw_len) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[2];
    char *argv[2];
    SW_REDIS_COMMAND_ARGV_FILL("AUTH", 4)
    SW_REDIS_COMMAND_ARGV_FILL(pw, pw_len)
    SW_REDIS_COMMAND(2)
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, save)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SAVE", 4);
}

static PHP_METHOD(swoole_redis_coro, bgSave)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "BGSAVE", 6);
}

static PHP_METHOD(swoole_redis_coro, lastSave)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LASTSAVE", 8);
}

static PHP_METHOD(swoole_redis_coro, flushDB)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "FLUSHDB", 7);
}

static PHP_METHOD(swoole_redis_coro, flushAll)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "FLUSHALL", 8);
}

static PHP_METHOD(swoole_redis_coro, dbSize)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DBSIZE", 6);
}

static PHP_METHOD(swoole_redis_coro, bgrewriteaof)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "BGREWRITEAOF", 12);
}

static PHP_METHOD(swoole_redis_coro, time)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "TIME", 4);
}

static PHP_METHOD(swoole_redis_coro, role)
{
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ROLE", 4);
}

static PHP_METHOD(swoole_redis_coro, setRange)
{
	sw_redis_command_key_long_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SETRANGE", 8);
}

static PHP_METHOD(swoole_redis_coro, setNx)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SETNX", 5);
}

static PHP_METHOD(swoole_redis_coro, getSet)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "GETSET", 6);
}

static PHP_METHOD(swoole_redis_coro, append)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "APPEND", 6);
}

static PHP_METHOD(swoole_redis_coro, lPushx)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LPUSHX", 6);
}

static PHP_METHOD(swoole_redis_coro, lPush)
{
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LPUSH", 5);
}

static PHP_METHOD(swoole_redis_coro, rPush)
{
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RPUSH", 5);
}

static PHP_METHOD(swoole_redis_coro, rPushx)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "RPUSHX", 6);
}

static PHP_METHOD(swoole_redis_coro, sContains)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SISMEMBER", 9);
}

static PHP_METHOD(swoole_redis_coro, zRange)
{
    char *key;
    zend_size_t key_len;
    long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE)
    {
        return;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc;
    argc = ZEND_NUM_ARGS() + 1;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZRANGE", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char buf[32];
    size_t buf_len;
    buf_len = snprintf(buf, sizeof(buf), "%ld", start);
    SW_REDIS_COMMAND_ARGV_FILL((char* )buf, buf_len)
    buf_len = snprintf(buf, sizeof(buf), "%ld", end);
    SW_REDIS_COMMAND_ARGV_FILL((char* )buf, buf_len)
    if (ws)
    {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    }
    else
    {
        argc = 4;
    }
    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zRevRange)
{
    char *key;
    zend_size_t key_len;
    long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

    int i = 0, argc;
    argc = ZEND_NUM_ARGS() + 1;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZREVRANGE", 9)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char buf[32];
    size_t buf_len;
    buf_len = snprintf(buf, sizeof(buf), "%ld", start);
    SW_REDIS_COMMAND_ARGV_FILL((char* )buf, buf_len)
    buf_len = snprintf(buf, sizeof(buf), "%ld", end);
    SW_REDIS_COMMAND_ARGV_FILL((char* )buf, buf_len)
    if (ws)
    {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    }
    else
    {
        argc = 4;
    }
    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zUnion)
{
    char *key, *agg_op;
    zend_size_t key_len;
    zval *z_keys, *z_weights=NULL;
    HashTable *ht_keys, *ht_weights=NULL;
    zend_size_t argc = 2, agg_op_len=0, keys_count;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa|a!s", &key,
                             &key_len, &z_keys, &z_weights, &agg_op,
                             &agg_op_len) == FAILURE)
    {
		return;
    }

    ht_keys = Z_ARRVAL_P(z_keys);

    if((keys_count = zend_hash_num_elements(ht_keys)) == 0) {
		RETURN_FALSE;
    } else {
        argc += keys_count + 1;
    }

    if(z_weights != NULL) {
        ht_weights = Z_ARRVAL_P(z_weights);
        if(zend_hash_num_elements(ht_weights) != keys_count) {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "WEIGHTS and keys array should be the same size!" TSRMLS_CC);
			RETURN_FALSE;
        }

        argc += keys_count + 1;
    }

    // AGGREGATE option
    if(agg_op_len != 0) {
        if(strncasecmp(agg_op, "SUM", sizeof("SUM")) &&
           strncasecmp(agg_op, "MIN", sizeof("MIN")) &&
           strncasecmp(agg_op, "MAX", sizeof("MAX")))
        {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid AGGREGATE option provided!" TSRMLS_CC);
			RETURN_FALSE;
        }

        // "AGGREGATE" + type
        argc += 2;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0, j;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZUNIONSTORE", 11)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	char buf[32];
	size_t buf_len;
    buf_len = sprintf(buf, "%d", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
	zval *value;
	SW_HASHTABLE_FOREACH_START(ht_keys, value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();

    // Weights
    if(ht_weights != NULL) {
		SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

		SW_HASHTABLE_FOREACH_START(ht_weights, value)
            if(SW_Z_TYPE_P(value) != IS_LONG && SW_Z_TYPE_P(value) != IS_DOUBLE &&
               strncasecmp(Z_STRVAL_P(value),"inf",sizeof("inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"-inf",sizeof("-inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"+inf",sizeof("+inf")) != 0)
            {
				zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
				zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "Weights must be numeric or '-inf','inf','+inf'" TSRMLS_CC);
				for (j = 0; j < i; j++)
				{
					efree((void* )argv[j]);
				}
				SW_REDIS_COMMAND_FREE_ARGV
				RETURN_FALSE;
            }
            switch (SW_Z_TYPE_P(value)) {
                case IS_LONG:
					buf_len = sprintf(buf, "%ld", Z_LVAL_P(value));
					SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                    break;
                case IS_DOUBLE:
					buf_len = sprintf(buf, "%f", Z_DVAL_P(value));
					SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                    break;
                case IS_STRING:
					SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
                    break;
            }
		SW_HASHTABLE_FOREACH_END();
    }

    // AGGREGATE
    if(agg_op_len != 0) {
		SW_REDIS_COMMAND_ARGV_FILL("AGGREGATE", 9)
		SW_REDIS_COMMAND_ARGV_FILL(agg_op, agg_op_len)
    }

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zInter)
{
    char *key, *agg_op;
    zend_size_t key_len;
    zval *z_keys, *z_weights=NULL;
    HashTable *ht_keys, *ht_weights=NULL;
    zend_size_t argc = 2, agg_op_len=0, keys_count;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa|a!s", &key,
                             &key_len, &z_keys, &z_weights, &agg_op,
                             &agg_op_len) == FAILURE)
    {
		return;
    }

    ht_keys = Z_ARRVAL_P(z_keys);

    if((keys_count = zend_hash_num_elements(ht_keys)) == 0) {
		RETURN_FALSE;
    } else {
        argc += keys_count + 1;
    }

    if(z_weights != NULL) {
        ht_weights = Z_ARRVAL_P(z_weights);
        if(zend_hash_num_elements(ht_weights) != keys_count) {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "WEIGHTS and keys array should be the same size!" TSRMLS_CC);
			RETURN_FALSE;
        }

        argc += keys_count + 1;
    }

    // AGGREGATE option
    if(agg_op_len != 0) {
        if(strncasecmp(agg_op, "SUM", sizeof("SUM")) &&
           strncasecmp(agg_op, "MIN", sizeof("MIN")) &&
           strncasecmp(agg_op, "MAX", sizeof("MAX")))
        {
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid AGGREGATE option provided!" TSRMLS_CC);
			RETURN_FALSE;
        }

        // "AGGREGATE" + type
        argc += 2;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0, j;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZINTERSTORE", 11)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	char buf[32];
	size_t buf_len;
    buf_len = sprintf(buf, "%d", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
	zval *value;
	SW_HASHTABLE_FOREACH_START(ht_keys, value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();

    // Weights
    if(ht_weights != NULL) {
		SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

		SW_HASHTABLE_FOREACH_START(ht_weights, value)
            if(SW_Z_TYPE_P(value) != IS_LONG && SW_Z_TYPE_P(value) != IS_DOUBLE &&
               strncasecmp(Z_STRVAL_P(value),"inf",sizeof("inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"-inf",sizeof("-inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"+inf",sizeof("+inf")) != 0)
            {
				zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
				zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Weights must be numeric or '-inf','inf','+inf'" TSRMLS_CC);
				for (j = 0; j < i; j++)
				{
					efree((void* )argv[j]);
				}
				SW_REDIS_COMMAND_FREE_ARGV
				RETURN_FALSE;
            }
            switch (SW_Z_TYPE_P(value)) {
                case IS_LONG:
					buf_len = sprintf(buf, "%ld", Z_LVAL_P(value));
					SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                    break;
                case IS_DOUBLE:
					buf_len = sprintf(buf, "%f", Z_DVAL_P(value));
					SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                    break;
                case IS_STRING:
					SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
                    break;
            }
		SW_HASHTABLE_FOREACH_END();
    }

    // AGGREGATE
    if(agg_op_len != 0) {
		SW_REDIS_COMMAND_ARGV_FILL("AGGREGATE", 9)
		SW_REDIS_COMMAND_ARGV_FILL(agg_op, agg_op_len)
    }

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zRangeByLex)
{
    char *key, *min, *max;
    zend_size_t key_len, min_len, max_len;
    long offset, count;
    zend_size_t argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if(argc != 3 && argc != 5) {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments" TSRMLS_CC);
        RETURN_FALSE;
    }

    if(zend_parse_parameters(argc TSRMLS_CC, "sss|ll", &key,
                             &key_len, &min, &min_len, &max, &max_len,
                             &offset, &count)==FAILURE)
    {
        RETURN_FALSE;
    }

    /* min and max must start with '(' or '[', or be either '-' or '+' */
    if(min_len < 1 || max_len < 1 ||
       (min[0] != '(' && min[0] != '[' &&
       (min[0] != '-' || min_len > 1) && (min[0] != '+' || min_len > 1)) ||
       (max[0] != '(' && max[0] != '[' &&
       (max[0] != '-' || max_len > 1) && (max[0] != '+' || max_len > 1)))
    {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "min and max arguments must start with '[' or '('" TSRMLS_CC);
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK

	argc = argc == 3 ? 4 : 7;
	int i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZRANGEBYLEX", 11)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(min, min_len)
	SW_REDIS_COMMAND_ARGV_FILL(max, max_len)
	if (argc == 7)
	{
		SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
		char buf[32];
		size_t buf_len;
		buf_len = sprintf(buf, "%ld", offset);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
		buf_len = sprintf(buf, "%ld", count);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
	}
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zRevRangeByLex)
{
    char *key, *min, *max;
    zend_size_t key_len, min_len, max_len;
    long offset, count;
    int argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if(argc != 3 && argc != 5) {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments" TSRMLS_CC);
        RETURN_FALSE;
    }

    if(zend_parse_parameters(argc TSRMLS_CC, "sss|ll", &key,
                             &key_len, &min, &min_len, &max, &max_len,
                             &offset, &count)==FAILURE)
    {
        RETURN_FALSE;
    }

    /* min and max must start with '(' or '[', or be either '-' or '+' */
    if(min_len < 1 || max_len < 1 ||
       (min[0] != '(' && min[0] != '[' &&
       (min[0] != '-' || min_len > 1) && (min[0] != '+' || min_len > 1)) ||
       (max[0] != '(' && max[0] != '[' &&
       (max[0] != '-' || max_len > 1) && (max[0] != '+' || max_len > 1)))
    {
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "min and max arguments must start with '[' or '('" TSRMLS_CC);
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK

	argc = argc == 3 ? 4 : 7;
	int i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZREVRANGEBYLEX", 14)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(min, min_len)
	SW_REDIS_COMMAND_ARGV_FILL(max, max_len)
	if (argc == 7)
	{
		SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
		char buf[32];
		size_t buf_len;
		buf_len = sprintf(buf, "%ld", offset);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
		buf_len = sprintf(buf, "%ld", count);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
	}
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zRangeByScore)
{
    char *key;
    zend_size_t key_len;
    char *start, *end;
    zend_size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt=NULL, *z_ele;
	zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sss|a", &key, &key_len, &start, &start_len, &end, &end_len,
            &z_opt) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

    int argc = 4, i = 0;
    // Check for an options array
    if (z_opt && Z_TYPE_P(z_opt) == IS_ARRAY)
    {
        ht_opt = Z_ARRVAL_P(z_opt);

        // Check for WITHSCORES
		if (sw_zend_hash_find(ht_opt, ZEND_STRS("withscores"), (void **) &z_ele) == SUCCESS
#if PHP_MAJOR_VERSION < 7
			&& Z_TYPE_P(z_ele) == IS_BOOL && Z_BVAL_P(z_ele) == 1
#else
            && Z_TYPE_P(z_ele) == IS_TRUE
#endif
		)
		{
			withscores = 1;
			argc++;
		}

        // LIMIT
		if (sw_zend_hash_find(ht_opt, ZEND_STRS("limit"), (void **) &z_ele) == SUCCESS)
        {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
#if PHP_MAJOR_VERSION < 7
            zval **z_off, **z_cnt;
            if (zend_hash_index_find(ht_limit,0,(void**)&z_off) == SUCCESS &&
               zend_hash_index_find(ht_limit,1,(void**)&z_cnt) == SUCCESS &&
               SW_Z_TYPE_PP(z_off) == IS_LONG && SW_Z_TYPE_PP(z_cnt) == IS_LONG)
            {
                has_limit  = 1;
                limit_low  = Z_LVAL_PP(z_off);
                limit_high = Z_LVAL_PP(z_cnt);
                argc += 3;
            }
#else
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit, 0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && SW_Z_TYPE_P(z_off) == IS_LONG && SW_Z_TYPE_P(z_cnt) == IS_LONG)
            {
                has_limit = 1;
                limit_low = Z_LVAL_P(z_off);
                limit_high = Z_LVAL_P(z_cnt);
                argc += 3;
            }
#endif
        }
    }
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZRANGEBYSCORE", 13)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(start, start_len)
	SW_REDIS_COMMAND_ARGV_FILL(end, end_len)

	if (withscores)
	{
		SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
	}
	if (has_limit)
	{
		SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
		char buf[32];
		size_t buf_len;
		buf_len = sprintf(buf, "%ld", limit_low);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
		buf_len = sprintf(buf, "%ld", limit_high);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
	}
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zRevRangeByScore)
{
    char *key;
    zend_size_t key_len;
    char *start, *end;
    zend_size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt=NULL, *z_ele;
	zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sss|a", &key, &key_len, &start, &start_len, &end, &end_len,
            &z_opt) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

    int argc = 4, i = 0;
    // Check for an options array
    if (z_opt && Z_TYPE_P(z_opt) == IS_ARRAY)
    {
        ht_opt = Z_ARRVAL_P(z_opt);

        // Check for WITHSCORES
		if (sw_zend_hash_find(ht_opt, ZEND_STRS("withscores"), (void **) &z_ele) == SUCCESS
#if PHP_MAJOR_VERSION < 7
            && Z_TYPE_P(z_ele) == IS_BOOL && Z_BVAL_P(z_ele) == 1
#else
            && Z_TYPE_P(z_ele) == IS_TRUE
#endif
		)
		{
			withscores = 1;
			argc++;
		}

        // LIMIT
		if (sw_zend_hash_find(ht_opt, ZEND_STRS("limit"), (void **) &z_ele) == SUCCESS)
        {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
#if PHP_MAJOR_VERSION < 7
            zval **z_off, **z_cnt;
            if (zend_hash_index_find(ht_limit,0,(void**)&z_off) == SUCCESS &&
               zend_hash_index_find(ht_limit,1,(void**)&z_cnt) == SUCCESS &&
               SW_Z_TYPE_PP(z_off) == IS_LONG && SW_Z_TYPE_PP(z_cnt) == IS_LONG)
            {
                has_limit  = 1;
                limit_low  = Z_LVAL_PP(z_off);
                limit_high = Z_LVAL_PP(z_cnt);
                argc += 3;
            }
#else
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit,0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && SW_Z_TYPE_P(z_off) == IS_LONG && SW_Z_TYPE_P(z_cnt) == IS_LONG)
            {
                has_limit = 1;
                limit_low = Z_LVAL_P(z_off);
                limit_high = Z_LVAL_P(z_cnt);
                argc += 3;
            }
#endif
        }
    }
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZREVRANGEBYSCORE", 16)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(start, start_len)
	SW_REDIS_COMMAND_ARGV_FILL(end, end_len)

	if (withscores)
	{
		SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
	}
	if (has_limit)
	{
		SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
		char buf[32];
		size_t buf_len;
		buf_len = sprintf(buf, "%ld", limit_low);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
		buf_len = sprintf(buf, "%ld", limit_high);
		SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
	}
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zIncrBy)
{
    char *key;
    zend_size_t key_len;
    double incrby;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sdz", &key, &key_len, &incrby, &z_val) == FAILURE)
    {
        return;
    }

	SW_REDIS_COMMAND_CHECK;

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("ZINCRBY", 7)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char buf[32];
	size_t buf_len;
    buf_len = sprintf(buf, "%f", incrby);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)
	SW_REDIS_COMMAND(4)
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zAdd)
{
    int argc = ZEND_NUM_ARGS();

    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE)
    {
        efree(z_args);
        RETURN_FALSE;
    }

#if PHP_MAJOR_VERSION < 7
    if (argc > 0) convert_to_string(z_args[0]);
#else
    if (argc > 0)
    {
        convert_to_string(&z_args[0]);
    }
#endif
    if (argc < 3 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING) {
        efree(z_args);
		RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS

	int i = 0, j, k, valid_params;
	valid_params = argc - 1;
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("ZADD", 4)
	SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), (size_t)SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
	k = 1;

	if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING && IS_NX_XX_ARG(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k])))
	{
		SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]), (size_t)SW_REDIS_COMMAND_ARGS_STRLEN(z_args[k]))
		k++;
		valid_params--;
	}

	if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING && strncasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]), "CH", 2) == 0)
	{
		SW_REDIS_COMMAND_ARGV_FILL("CH", 2)
		k++;
		valid_params--;
	}

	if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING && strncasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]), "INCR", 4) == 0)
	{
		SW_REDIS_COMMAND_ARGV_FILL("INCR", 4)
		k++;
		valid_params--;
	}

	if (valid_params % 2 != 0)
	{
		for (i = 0; i < 1 + k; i++)
		{
			efree((void* )argv[i]);
		}
		SW_REDIS_COMMAND_FREE_ARGV
		efree(z_args);
		RETURN_FALSE;
	}

	char buf[32];
	size_t buf_len;
    for (j = k; j < argc-1; j += 2) {
        convert_to_double(SW_REDIS_COMMAND_ARGS_REF(z_args[j])); buf_len = snprintf(buf, sizeof(buf), "%f", SW_REDIS_COMMAND_ARGS_DVAL(z_args[j]));
		SW_REDIS_COMMAND_ARGV_FILL((char*)buf, buf_len)
		SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(SW_REDIS_COMMAND_ARGS_REF(z_args[j+1]))
    }
    efree(z_args);

	SW_REDIS_COMMAND(argc);
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zScore)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZSCORE", 6);
}

static PHP_METHOD(swoole_redis_coro, zRank)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZRANK", 5);
}

static PHP_METHOD(swoole_redis_coro, zRevRank)
{
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZREVRANK", 8);
}

static PHP_METHOD(swoole_redis_coro, hGet)
{
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HGET", 4);
}

static PHP_METHOD(swoole_redis_coro, hMGet)
{
    char *key;
    zval *z_arr;
    zend_size_t argc, key_len;
    HashTable *ht_chan;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &key, &key_len,
                             &z_arr)==FAILURE)
    {
        return;
    }

    ht_chan = Z_ARRVAL_P(z_arr);

    if((argc = zend_hash_num_elements(ht_chan)) == 0) {
        RETURN_FALSE;
    }
	SW_REDIS_COMMAND_CHECK

	zval *value;
	int i = 0;
	argc = argc + 2;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("HMGET", 5)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_HASHTABLE_FOREACH_START(ht_chan, value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hExists)
{
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "HEXISTS", 7);
}

static PHP_METHOD(swoole_redis_coro, publish)
{
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PUBLISH", 7);
}

static PHP_METHOD(swoole_redis_coro, zDeleteRangeByScore)
{
    sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZREMRANGEBYSCORE", 16);
}

static PHP_METHOD(swoole_redis_coro, zCount)
{
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZCOUNT", 6);
}

static PHP_METHOD(swoole_redis_coro, incrBy)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "INCRBY", 6);
}

static PHP_METHOD(swoole_redis_coro, hIncrBy)
{
    char *key, *mem;
    zend_size_t key_len, mem_len;
    long byval;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl", &key, &key_len,
                             &mem, &mem_len, &byval)==FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("HINCRBY", 7)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(mem, mem_len)
    char str[32];
    sprintf(str, "%ld", byval);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hIncrByFloat)
{
    char *key, *mem;
    zend_size_t key_len, mem_len;
    double byval;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssd", &key, &key_len,
                             &mem, &mem_len, &byval)==FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("HINCRBYFLOAT", 12)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(mem, mem_len)
    char str[32];
    sprintf(str, "%f", byval);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, incr)
{
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "INCR", 4);
}

static PHP_METHOD(swoole_redis_coro, decrBy)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DECRBY", 6);
}

static PHP_METHOD(swoole_redis_coro, decr)
{
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, "DECR", 4);
}

static PHP_METHOD(swoole_redis_coro, getBit)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "GETBIT", 6);
}

static PHP_METHOD(swoole_redis_coro, lInsert)
{
    char *key, *pos;
    zend_size_t key_len, pos_len;
    zval *z_val, *z_pivot;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sszz", &key, &key_len,
                             &pos, &pos_len, &z_pivot, &z_val) == FAILURE)
    {
        return;
    }

	if (strncasecmp(pos, "after", 5) && strncasecmp(pos, "before", 6)) {
		swoole_php_error(E_WARNING, "Position must be either 'BEFORE' or 'AFTER'");
		RETURN_FALSE;
	}

	SW_REDIS_COMMAND_CHECK

	int i = 0;
    size_t argvlen[5];
    char *argv[5];

	SW_REDIS_COMMAND_ARGV_FILL("LINSERT", 7)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
	SW_REDIS_COMMAND_ARGV_FILL(pos, pos_len)
	SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_pivot)
	SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)
	SW_REDIS_COMMAND(5);
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, lGet)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LINDEX", 6);
}

static PHP_METHOD(swoole_redis_coro, setTimeout)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "EXPIRE", 6);
}

static PHP_METHOD(swoole_redis_coro, pexpire)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PEXPIRE", 7);
}

static PHP_METHOD(swoole_redis_coro, expireAt)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "EXPIREAT", 8);
}

static PHP_METHOD(swoole_redis_coro, pexpireAt)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PEXPIREAT", 9);
}

static PHP_METHOD(swoole_redis_coro, move)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "MOVE", 4);
}

static PHP_METHOD(swoole_redis_coro, select)
{
    long db_number;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &db_number) == FAILURE) {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0;
    size_t argvlen[2];
    char *argv[2];

	SW_REDIS_COMMAND_ARGV_FILL("SELECT", 6)
	char str[32];
	sprintf(str, "%ld", db_number);
	SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
	SW_REDIS_COMMAND(2);
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, getRange)
{
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "GETRANGE", 8);
}

static PHP_METHOD(swoole_redis_coro, listTrim)
{
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LTRIM", 5);
}

static PHP_METHOD(swoole_redis_coro, lGetRange)
{
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "LRANGE", 6);
}

static PHP_METHOD(swoole_redis_coro, lRem)
{
    char *key;
    zend_size_t key_len;
    long count = 0;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|l", &key, &key_len,
                             &z_val, &count) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("LREM", 4)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%d", (int)count);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, zDeleteRangeByRank)
{
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZREMRANGEBYRANK", 15);
}

static PHP_METHOD(swoole_redis_coro, incrByFloat)
{
    sw_redis_command_key_dbl(INTERNAL_FUNCTION_PARAM_PASSTHRU, "INCRBYFLOAT", 11);
}

static PHP_METHOD(swoole_redis_coro, bitCount)
{
    char *key;
    zend_size_t key_len;
    long start = 0, end = -1;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &key, &key_len,
                             &start, &end)==FAILURE)
    {
        return;
    }

	SW_REDIS_COMMAND_CHECK

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("BITCOUNT", 8)
	SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%d", (int)start);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    sprintf(str, "%d", (int)end);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))

	SW_REDIS_COMMAND(4)

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, bitOp)
{
    int argc = ZEND_NUM_ARGS();

    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if(zend_get_parameters_array(ht, argc, z_args) == FAILURE ||
       argc < 3 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING)
    {
        efree(z_args);
        return;
    }

	SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS

	int j, i = 0;
	argc++;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("BITOP", 5)
	SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
    for(j = 1; j < argc - 1; j++) {
#if PHP_MAJOR_VERSION < 7
        convert_to_string(z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	}
	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV
    efree(z_args);
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, sMove)
{
    char *src, *dst;
    zend_size_t src_len, dst_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &src, &src_len,
                             &dst, &dst_len, &z_val) == FAILURE)
    {
        return;
    }
	SW_REDIS_COMMAND_CHECK

	int i = 0;
	size_t argvlen[4];
	char *argv[4];
	SW_REDIS_COMMAND_ARGV_FILL("SMOVE", 5)
	SW_REDIS_COMMAND_ARGV_FILL(src, src_len)
	SW_REDIS_COMMAND_ARGV_FILL(dst, dst_len)
	SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)
	SW_REDIS_COMMAND(4)
	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, sAdd)
{
	sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SADD", 4);
}

static PHP_METHOD(swoole_redis_coro, sRemove)
{
	sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SREM", 4);
}

static PHP_METHOD(swoole_redis_coro, zDelete)
{
	sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZREM", 4);
}

static PHP_METHOD(swoole_redis_coro, pSubscribe)
{
    zval *z_arr;
    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &z_arr) == FAILURE)
    {
		return;
    }

    swRedisClient *redis = swoole_get_object(getThis());
	if (redis->defer)
	{
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "psubscribe cannot be used with defer enabled" TSRMLS_CC);
		RETURN_FALSE;
	}

    if (unlikely(redis->cid && redis->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "redis client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

	php_context *context = swoole_get_property(getThis(), 0);
    switch (redis->state)
    {
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE:
		coro_save(context);
		redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
		coro_yield();
		break;
    case SWOOLE_REDIS_CORO_STATE_CONNECT:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is not connected." TSRMLS_CC);
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_CLOSED:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client connection is closed." TSRMLS_CC);
        RETURN_FALSE;
        break;
	case SWOOLE_REDIS_CORO_STATE_MULTI:
	case SWOOLE_REDIS_CORO_STATE_PIPELINE:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is multi or pipeline, cann't use subscribe cmd." TSRMLS_CC);
        RETURN_FALSE;
        break;
    default:
        break;
    }

    HashTable *ht_chan = Z_ARRVAL_P(z_arr);
    int argc = 1 + zend_hash_num_elements(ht_chan), i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("PSUBSCRIBE", 10)

	zval *value;
	SW_HASHTABLE_FOREACH_START(ht_chan, value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV

    redis->state = SWOOLE_REDIS_CORO_STATE_SUBSCRIBE;

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, subscribe)
{
    zval *z_arr;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "a", &z_arr) == FAILURE)
    {
		return;
    }

    swRedisClient *redis = swoole_get_object(getThis());
	if (redis->defer)
	{
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "subscribe cannot be used with defer enabled" TSRMLS_CC);
		RETURN_FALSE;
	}

    if (unlikely(redis->cid && redis->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "redis client has already been bound to another coroutine.");
        RETURN_FALSE;
    }

	php_context *context = swoole_get_property(getThis(), 0);
    switch (redis->state)
    {
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE:
		coro_save(context);
		redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
		coro_yield();
		break;
    case SWOOLE_REDIS_CORO_STATE_CONNECT:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is not connected." TSRMLS_CC);
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_CLOSED:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client connection is closed." TSRMLS_CC);
        RETURN_FALSE;
        break;
	case SWOOLE_REDIS_CORO_STATE_MULTI:
	case SWOOLE_REDIS_CORO_STATE_PIPELINE:
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is multi or pipeline, cann't use subscribe cmd." TSRMLS_CC);
        RETURN_FALSE;
        break;
    default:
        break;
    }

    HashTable *ht_chan = Z_ARRVAL_P(z_arr);
    int argc = 1 + zend_hash_num_elements(ht_chan), i = 0;
	SW_REDIS_COMMAND_ALLOC_ARGV
	SW_REDIS_COMMAND_ARGV_FILL("SUBSCRIBE", 9)

	zval *value;
	SW_HASHTABLE_FOREACH_START(ht_chan, value)
#if PHP_MAJOR_VERSION < 7
        convert_to_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(value), Z_STRLEN_P(value))
#else
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
#endif
	SW_HASHTABLE_FOREACH_END();

	SW_REDIS_COMMAND(argc)
	SW_REDIS_COMMAND_FREE_ARGV

    redis->state = SWOOLE_REDIS_CORO_STATE_SUBSCRIBE;

	SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, multi)
{
    long mode = SW_REDIS_MODE_MULTI;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &mode) == FAILURE)
    {
		return;
    }

	SW_REDIS_COMMAND_CHECK

	if (mode == SW_REDIS_MODE_MULTI)
	{
		redis->state = SWOOLE_REDIS_CORO_STATE_MULTI;
		size_t argvlen[1];
		char *argv[1];
		argvlen[0] = 5;
		argv[0] = estrndup("MULTI", 5);
		if (redisAsyncCommandArgv(redis->context, swoole_redis_coro_onResult, NULL, 1, (const char **) argv, (const size_t *) argvlen) < 0)
		{
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed." TSRMLS_CC);
			RETURN_FALSE;
		}
		efree(argv[0]);

		redis->queued_cmd_count = 2;
	}
	else
	{
		redis->state = SWOOLE_REDIS_CORO_STATE_PIPELINE;
		redis->queued_cmd_count = 0;
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, exec)
{
    coro_check(TSRMLS_C);
    swRedisClient *redis = swoole_get_object(getThis());
	if (redis->state != SWOOLE_REDIS_CORO_STATE_MULTI && redis->state != SWOOLE_REDIS_CORO_STATE_PIPELINE)
	{
		zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
		zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is neither multi nor pipeline!" TSRMLS_CC);
		RETURN_FALSE;
	}
    if (unlikely(redis->cid && redis->cid != get_current_cid()))
    {
        swoole_php_fatal_error(E_WARNING, "redis client has already been bound to another coroutine.");
        RETURN_FALSE;
    }
	if (redis->state == SWOOLE_REDIS_CORO_STATE_MULTI)
	{
		size_t argvlen[1];
		char *argv[1];
		argvlen[0] = 4;
		argv[0] = estrndup("EXEC", 4);
		if (redisAsyncCommandArgv(redis->context, swoole_redis_coro_onResult, NULL, 1, (const char **) argv, (const size_t *) argvlen) < 0)
		{
			zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER TSRMLS_CC);
			zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed." TSRMLS_CC);
			RETURN_FALSE;
		}
		efree(argv[0]);
	}
	redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
	if (redis->defer)
	{
		RETURN_TRUE;
	}
    redis->cid = get_current_cid();
	php_context *context = swoole_get_property(getThis(), 0);
	coro_save(context);
	coro_yield();
}

static PHP_METHOD(swoole_redis_coro, request)
{
    SW_REDIS_COMMAND_CHECK

    zval *params = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &params) == FAILURE)
    {
        return;
    }

    int argc = zend_hash_num_elements(Z_ARRVAL_P(params));
    size_t stack_argvlen[SW_REDIS_COMMAND_BUFFER_SIZE];
    char *stack_argv[SW_REDIS_COMMAND_BUFFER_SIZE];

    size_t *argvlen;
    char **argv;
    zend_bool free_mm = 0;
    int i = 0;

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

    zval *value;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
        if (i == argc)
        {
            break;
        }

        zend_string *convert_str = zval_get_string(value);
        argvlen[i] = convert_str->len;
        argv[i] = estrndup(convert_str->val, convert_str->len);
        zend_string_release(convert_str);
        i++;
    SW_HASHTABLE_FOREACH_END();

    SW_REDIS_COMMAND(argc)

    if (free_mm)
    {
        efree(argvlen);
        efree(argv);
    }
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, eval)
{
    char *script;
    zend_size_t script_len;
    zval *params = NULL;
    long keys_num = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|al", &script, &script_len, &params, &keys_num) == FAILURE)
    {
        return;
    }

    HashTable *params_ht = NULL;
    uint32_t params_num = 0;
    if (params) {
        params_ht = Z_ARRVAL_P(params);
        params_num = zend_hash_num_elements(params_ht);
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t *argvlen = emalloc(sizeof(size_t) * (params_num + 3));
    char **argv = emalloc(sizeof(char *) * (params_num + 3));

    SW_REDIS_COMMAND_ARGV_FILL("EVAL", 4)
    SW_REDIS_COMMAND_ARGV_FILL(script, script_len)

    char keys_num_str[32] = {0};
    sprintf(keys_num_str, "%ld", keys_num);
    SW_REDIS_COMMAND_ARGV_FILL(keys_num_str, strlen(keys_num_str));

    if (params_ht) {
        zval *param;
        SW_HASHTABLE_FOREACH_START(params_ht, param)
#if PHP_MAJOR_VERSION < 7
            convert_to_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(param), Z_STRLEN_P(param))
#else
            zend_string *param_str = zval_get_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(param_str->val, param_str->len)
            zend_string_release(param_str);
#endif
        SW_HASHTABLE_FOREACH_END();
    }

    SW_REDIS_COMMAND(params_num + 3)
    efree(argvlen);
    efree(argv);
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, evalSha)
{
    char *sha;
    zend_size_t sha_len;
    zval *params = NULL;
    long keys_num = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|al", &sha, &sha_len, &params, &keys_num) == FAILURE)
    {
        return;
    }

    HashTable *params_ht = NULL;
    uint32_t params_num = 0;
    if (params) {
        params_ht = Z_ARRVAL_P(params);
        params_num = zend_hash_num_elements(params_ht);
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t *argvlen = emalloc(sizeof(size_t) * (params_num + 3));
    char **argv = emalloc(sizeof(char *) * (params_num + 3));

    SW_REDIS_COMMAND_ARGV_FILL("EVALSHA", 7)
    SW_REDIS_COMMAND_ARGV_FILL(sha, sha_len)

    char keys_num_str[32] = {0};
    sprintf(keys_num_str, "%ld", keys_num);
    SW_REDIS_COMMAND_ARGV_FILL(keys_num_str, strlen(keys_num_str));

    if (params) {
        zval *param;
        SW_HASHTABLE_FOREACH_START(params_ht, param)
#if PHP_MAJOR_VERSION < 7
            convert_to_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(param), Z_STRLEN_P(param))
#else
            zend_string *param_str = zval_get_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(param_str->val, param_str->len)
            zend_string_release(param_str);
#endif
        SW_HASHTABLE_FOREACH_END();
    }

    SW_REDIS_COMMAND(params_num + 3)
    efree(argvlen);
    efree(argv);
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, script)
{
    int argc = ZEND_NUM_ARGS();
    if (argc < 1) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING) {
        efree(z_args);
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0;
    if (! strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "flush") || ! strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "kill")) {
        size_t argvlen[2];
        char *argv[2];
        SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
        SW_REDIS_COMMAND(2)
        efree(z_args);
        SW_REDIS_COMMAND_YIELD
    } else if (! strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "exists")) {
        if (argc < 2) {
            efree(z_args);
            RETURN_FALSE;
        } else {
            size_t *argvlen = emalloc(sizeof(size_t) * (argc + 1));
            char **argv = emalloc(sizeof(char *) * (argc + 1));
            SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
            SW_REDIS_COMMAND_ARGV_FILL("EXISTS", 6)
            int j = 1;
            for (; j < argc; j++) {
#if PHP_MAJOR_VERSION < 7
                convert_to_string(z_args[j]);
                SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[j]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[j]))
#else
                zend_string *z_arg_str = zval_get_string(&z_args[j]);
                SW_REDIS_COMMAND_ARGV_FILL(z_arg_str->val, z_arg_str->len)
                zend_string_release(z_arg_str);
#endif
            }

            SW_REDIS_COMMAND(argc + 1)
            efree(argvlen);
            efree(argv);
            efree(z_args);
            SW_REDIS_COMMAND_YIELD
        }
    } else if (! strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "load")) {
        if (argc < 2 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[1]) != IS_STRING) {
            efree(z_args);
            RETURN_FALSE;
        } else {
            size_t argvlen[3];
            char *argv[3];
            SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
            SW_REDIS_COMMAND_ARGV_FILL("LOAD", 4)
            SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[1]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[1]))
            SW_REDIS_COMMAND(3)
            efree(z_args);
            SW_REDIS_COMMAND_YIELD
        }
    } else {
        efree(z_args);
        RETURN_FALSE;
    }
}

static void swoole_redis_coro_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC)
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
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr TSRMLS_CC);
        break;

    case REDIS_REPLY_STATUS:
        if (redis->context->err == 0)
        {
			if (reply->len > 0)
			{
				if (strncmp(reply->str, "OK", 2) == 0)
				{
					ZVAL_BOOL(return_value, 1);
					break;
				}
				long l;
				if (strncmp(reply->str, "string", 6) == 0) {
					l = SW_REDIS_STRING;
				} else if (strncmp(reply->str, "set", 3) == 0){
					l = SW_REDIS_SET;
				} else if (strncmp(reply->str, "list", 4) == 0){
					l = SW_REDIS_LIST;
				} else if (strncmp(reply->str, "zset", 4) == 0){
					l = SW_REDIS_ZSET;
				} else if (strncmp(reply->str, "hash", 4) == 0){
					l = SW_REDIS_HASH;
				} else {
					l = SW_REDIS_NOT_FOUND;
				}
				ZVAL_LONG(return_value, l);
			}
			else
			{
				ZVAL_TRUE(return_value);
			}
        }
        else
        {
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err TSRMLS_CC);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr TSRMLS_CC);
        }
        break;

    case REDIS_REPLY_STRING:
		if (redis->serialize)
		{
			char *reserve_str = reply->str;
			php_unserialize_data_t s_ht;
			PHP_VAR_UNSERIALIZE_INIT(s_ht);
#if PHP_MAJOR_VERSION < 7
			if(!php_var_unserialize(&return_value,
#else
            if(!php_var_unserialize(return_value,
#endif
                (const unsigned char**)&reply->str,
				(const unsigned char*)reply->str + reply->len, &s_ht TSRMLS_CC)) {
				SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
			}
			PHP_VAR_UNSERIALIZE_DESTROY(s_ht);
			reply->str = reserve_str;
		}
		else
		{
			SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
		}
        break;

    case REDIS_REPLY_ARRAY:
        array_init(return_value);
        for (j = 0; j < reply->elements; j++)
        {
#if PHP_MAJOR_VERSION < 7
            SW_ALLOC_INIT_ZVAL(val);
#endif
            swoole_redis_coro_parse_result(redis, val, reply->element[j] TSRMLS_CC);
            add_next_index_zval(return_value, val);
        }
        break;

    case REDIS_REPLY_NIL:
    default:
        ZVAL_NULL(return_value);
        return;
    }
}

static void swoole_redis_coro_resume(void *data)
{
    swRedis_result *result = (swRedis_result *) data;
    swRedisClient *redis = result->redis;
    zval *retval = NULL;
    zval *redis_result = NULL;

    if (redis->object == NULL)
    {
        goto free_result;
    }

    swTraceLog(SW_TRACE_REDIS_CLIENT, "resume, fd=%d, object_id=%d", redis->context->c.fd, sw_get_object_handle(redis->object));

    redis->cid = 0;
    redis->iowait = SW_REDIS_CORO_STATUS_READY;

    php_context *sw_current_context = swoole_get_property(redis->object, 0);

    redis_result = result->value;

    int ret = coro_resume(sw_current_context, redis_result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_result: if (redis_result)
    {
        sw_zval_ptr_dtor(&redis_result);
    }
    efree(result);
}

static void swoole_redis_coro_onResult(redisAsyncContext *c, void *r, void *privdata)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, c->c.fd);
    if (_socket->active == 0)
    {
        return;
    }

    swRedisClient *redis = c->ev.data;
    swRedis_result *result = emalloc(sizeof(swRedis_result));
    redisReply *reply = r;

#if PHP_MAJOR_VERSION < 7
    zval **type;
    SW_MAKE_STD_ZVAL(result->value);
#else
    zval *type;
    result->value = &result->_value;
    bzero(result->value, sizeof(result->_value));
#endif

    swTraceLog(SW_TRACE_REDIS_CLIENT, "get response, fd=%d, object_id=%d", redis->context->c.fd, sw_get_object_handle(redis->object));

    result->redis = redis;
    if (reply == NULL)
    {
		if (redis->state == SWOOLE_REDIS_CORO_STATE_CLOSING)
		{
            error:
            sw_zval_ptr_dtor(&result->value);
            efree(result);
            return;
		}
		ZVAL_FALSE(result->value);
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);
		if (redis->pipeline_result != NULL)
		{
			sw_zval_free(redis->pipeline_result);
			redis->pipeline_result = NULL;
        }
        swoole_redis_coro_resume(result);
        return;
    }
    else
    {
        swoole_redis_coro_parse_result(redis, result->value, reply TSRMLS_CC);

        switch (redis->state)
        {
        case SWOOLE_REDIS_CORO_STATE_PIPELINE:
            if (redis->pipeline_result == NULL)
            {
                SW_ALLOC_INIT_ZVAL(redis->pipeline_result);
                array_init(redis->pipeline_result);
            }
            redis->queued_cmd_count--;
            add_next_index_zval(redis->pipeline_result, result->value);
            if (redis->queued_cmd_count > 0)
            {
                goto error;
            }
            result->value = redis->pipeline_result;
            redis->pipeline_result = NULL;
            redis->state = SWOOLE_REDIS_CORO_STATE_READY;
            break;
        case SWOOLE_REDIS_CORO_STATE_MULTI:
            redis->queued_cmd_count--;
            if (redis->queued_cmd_count > 0)
            {
                goto error;
            }
            redis->state = SWOOLE_REDIS_CORO_STATE_READY;
            break;
        case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE:
#if PHP_MAJOR_VERSION < 7
            if (zend_hash_index_find(Z_ARRVAL_P(result->value), 0, (void **)&type) == FAILURE)
#else
            type = zend_hash_index_find(Z_ARRVAL_P(result->value), 0);
            if (!type)
#endif
            {
                goto error;
            }
#if PHP_MAJOR_VERSION < 7
            if (strncasecmp(Z_STRVAL_PP(type), "subscribe", 9) == 0 || strncasecmp(Z_STRVAL_PP(type), "psubscribe", 10) == 0)
#else
            if (strncasecmp(Z_STRVAL_P(type), "subscribe", 9) == 0 || strncasecmp(Z_STRVAL_P(type), "psubscribe", 10) == 0)
#endif
            {
                goto error;
            }
            redis->state = SWOOLE_REDIS_CORO_STATE_READY;
            break;
        default:
            if (redis->defer && !redis->defer_yield)
            {
                redis->iowait = SW_REDIS_CORO_STATUS_DONE;
                redis->defer_result = sw_zval_dup(result->value);
                efree(result);
                return;
            }
            else
            {
                redis->state = SWOOLE_REDIS_CORO_STATE_READY;
                break;
            }
        }
	}

    if (redis->state == SWOOLE_REDIS_CORO_STATE_READY)
    {
        /* et reactor defer callback */
        redis->iowait = SW_REDIS_CORO_STATUS_DONE;
        redis->defer_yield = 0;
        swoole_redis_coro_resume(result);
    }
}

void swoole_redis_coro_onConnect(const redisAsyncContext *c, int status)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    swRedisClient *redis = c->ev.data;
    swRedis_result *result = emalloc(sizeof(swRedis_result));

#if PHP_MAJOR_VERSION < 7
    MAKE_STD_ZVAL(result->value);
#else
    result->value = &result->_value;
    bzero(result->value, sizeof(result->_value));
#endif

    result->redis = redis;

    if (redis->timer)
    {
        swTimer_del(&SwooleG.timer, redis->timer);
        redis->timer = NULL;
    }

    if (status != REDIS_OK)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);
        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0 TSRMLS_CC);

        zval *retval = NULL;
        zval *redis_result = NULL;
        SW_MAKE_STD_ZVAL(redis_result);
        ZVAL_BOOL(redis_result, 0);

        php_context *sw_current_context = swoole_get_property(redis->object, 0);

        swoole_set_object(redis->object, NULL);
        SwooleG.main_reactor->defer(SwooleG.main_reactor, redis_coro_free, redis);

        int ret = coro_resume(sw_current_context, redis_result, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    else
    {
        ZVAL_BOOL(result->value, 1);
        redis->state = SWOOLE_REDIS_CORO_STATE_READY;
		redis->iowait = SW_REDIS_CORO_STATUS_READY;

	    swConnection *_socket = swReactor_get(SwooleG.main_reactor, c->c.fd);
        _socket->active = 1;

        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 1 TSRMLS_CC);

        redis->connecting = 1;
        redis->connected = 1;
        swoole_redis_coro_resume(result);
        redis->connecting = 0;
    }
}

static void swoole_redis_coro_onClose(const redisAsyncContext *c, int status)
{
    swRedisClient *redis = c->ev.data;
    redis->state = SWOOLE_REDIS_CORO_STATE_CLOSED;
    redis->connected = 0;

    if (redis->object)
    {
        swTraceLog(SW_TRACE_REDIS_CLIENT, "fd=%d, object_id=%d", redis->context->c.fd, sw_get_object_handle(redis->object));

        redis->context = NULL;
        redis->iowait = SW_REDIS_CORO_STATUS_CLOSED;
        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0 TSRMLS_CC);

        if (redis->iowait == SW_REDIS_CORO_STATUS_WAIT)
        {
            php_context *context = swoole_get_property(redis->object, 0);
            zval *retval = NULL;
            zval *redis_result;
            SW_MAKE_STD_ZVAL(redis_result);
            ZVAL_FALSE(redis_result);

            int ret = coro_resume(context, redis_result, &retval);
            if (ret == CORO_END && retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            sw_zval_ptr_dtor(&redis_result);
        }
    }

    if (redis->released)
    {
        efree(redis);
    }
}

static void swoole_redis_coro_event_AddRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_coro_event_DelRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_coro_event_AddWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_add_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

static void swoole_redis_coro_event_DelWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && SwooleG.main_reactor)
    {
        swReactor_del_event(SwooleG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

static void swoole_redis_coro_event_Cleanup(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    redis->state = SWOOLE_REDIS_CORO_STATE_CLOSED;
    if (redis->context && SwooleG.main_reactor)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, redis->context->c.fd);
    }
}

static int swoole_redis_coro_onError(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    swRedisClient *redis = event->socket->object;
    redisAsyncContext *c = redis->context;
	zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err TSRMLS_CC);
	zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr TSRMLS_CC);
    zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0 TSRMLS_CC);
	zval *retval = NULL;
	sw_zend_call_method_with_0_params(&redis->object, swoole_redis_coro_class_entry_ptr, NULL, "close", &retval);
	if (retval)
	{
		sw_zval_ptr_dtor(&retval);
	}

	return SW_OK;
}

static void swoole_redis_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *result;
    zval *retval = NULL;
    php_context *ctx = tnode->data;

    SW_ALLOC_INIT_ZVAL(result);
    ZVAL_BOOL(result, 0);

#if PHP_MAJOR_VERSION < 7
    zval *zobject = (zval *)ctx->coro_params;
#else
    zval _zobject = ctx->coro_params;
    zval *zobject = &_zobject;
#endif

    swRedisClient *redis = swoole_get_object(zobject);
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
    zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), strerror(ETIMEDOUT) TSRMLS_CC);
    redisAsyncDisconnect(redis->context);

    int ret = coro_resume(ctx, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_free(result);
}

static int swoole_redis_coro_onRead(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    swTraceLog(SW_TRACE_REDIS_CLIENT, "read event, fd=%d", redis->context->c.fd);
    redisAsyncHandleRead(redis->context);
    return SW_OK;
}

static int swoole_redis_coro_onWrite(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    swTraceLog(SW_TRACE_REDIS_CLIENT, "write event, fd=%d", redis->context->c.fd);
    redisAsyncHandleWrite(redis->context);
    return SW_OK;
}

#endif
#endif
