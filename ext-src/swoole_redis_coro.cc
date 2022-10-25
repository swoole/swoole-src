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

#include "php_swoole_cxx.h"

#include "thirdparty/hiredis/hiredis.h"

#include "ext/standard/php_var.h"

using swoole::coroutine::Socket;
using namespace swoole;

#define SW_REDIS_COMMAND_ALLOC_ARGS_ARR zval *z_args = (zval *) emalloc(argc * sizeof(zval));
#define SW_REDIS_COMMAND_ARGS_TYPE(arg) Z_TYPE(arg)
#define SW_REDIS_COMMAND_ARGS_LVAL(arg) Z_LVAL(arg)
#define SW_REDIS_COMMAND_ARGS_DVAL(arg) Z_DVAL(arg)
#define SW_REDIS_COMMAND_ARGS_ARRVAL(arg) Z_ARRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRVAL(arg) Z_STRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRLEN(arg) Z_STRLEN(arg)
#define SW_REDIS_COMMAND_ARGS_REF(arg) &arg

#define SW_REDIS_COMMAND_BUFFER_SIZE 64
#define SW_BITOP_MIN_OFFSET 0
#define SW_BITOP_MAX_OFFSET 4294967295
#define SW_REDIS_TYPE_NOT_FOUND 0
#define SW_REDIS_TYPE_STRING 1
#define SW_REDIS_TYPE_SET 2
#define SW_REDIS_TYPE_LIST 3
#define SW_REDIS_TYPE_ZSET 4
#define SW_REDIS_TYPE_HASH 5

/* The same errCode define with hiredis */
enum swRedisError {
    SW_REDIS_ERR_IO = 1,       /* Error in read or write */
    SW_REDIS_ERR_OTHER = 2,    /* Everything else... */
    SW_REDIS_ERR_EOF = 3,      /* End of file */
    SW_REDIS_ERR_PROTOCOL = 4, /* Protocol error */
    SW_REDIS_ERR_OOM = 5,      /* Out of memory */
    SW_REDIS_ERR_CLOSED = 6,   /* Closed */
    SW_REDIS_ERR_NOAUTH = 7,   /* Authentication required */
    SW_REDIS_ERR_ALLOC = 8,    /* Alloc failed */
};

/* Extended SET argument detection */
// clang-format off
#define IS_EX_ARG(a) \
    ((a[0]=='e' || a[0]=='E') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_PX_ARG(a) \
    ((a[0]=='p' || a[0]=='P') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_NX_ARG(a) \
    ((a[0]=='n' || a[0]=='N') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')
#define IS_XX_ARG(a) \
    ((a[0]=='x' || a[0]=='X') && (a[1]=='x' || a[1]=='X') && a[2]=='\0')

static zend_class_entry *swoole_redis_coro_ce;
static zend_object_handlers swoole_redis_coro_handlers;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, config)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, serialize)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setOptions, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setDefer, 0, 0, 1)
    ZEND_ARG_INFO(0, defer)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_request, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, params, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_append, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_auth, 0, 0, 1)
    ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bgSave, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bgrewriteaof, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bitcount, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bitop, 0, 0, 3)
    ZEND_ARG_INFO(0, operation)
    ZEND_ARG_INFO(0, ret_key)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_blPop, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timeout_or_key)
    ZEND_ARG_INFO(0, extra_args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_brPop, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timeout_or_key)
    ZEND_ARG_INFO(0, extra_args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_brpoplpush, 0, 0, 3)
    ZEND_ARG_INFO(0, src)
    ZEND_ARG_INFO(0, dst)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_close, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_dbSize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_debug, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_decr, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_decrBy, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_dump, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_eval, 0, 0, 1)
    ZEND_ARG_INFO(0, script)
    ZEND_ARG_INFO(0, args)
    ZEND_ARG_INFO(0, num_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_evalsha, 0, 0, 1)
    ZEND_ARG_INFO(0, script_sha)
    ZEND_ARG_INFO(0, args)
    ZEND_ARG_INFO(0, num_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_exec, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_expireAt, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timestamp)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_flushAll, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_flushDB, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_get, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_getBit, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_getKeys, 0, 0, 1)
    ZEND_ARG_INFO(0, pattern)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_getRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_getSet, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hDel, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, other_members)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hExists, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hGet, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hGetAll, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hIncrBy, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hIncrByFloat, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hKeys, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hLen, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hMget, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hMset, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, pairs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hSet, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hSetNx, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_hVals, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_incr, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_incrBy, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_incrByFloat, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lGet, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, index)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lGetRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lInsert, 0, 0, 4)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, position)
    ZEND_ARG_INFO(0, pivot)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lPop, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lPush, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lPushx, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lRemove, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lSet, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, index)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lSize, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lastSave, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_listTrim, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, stop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_move, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, dbindex)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_mset, 0, 0, 1)
    ZEND_ARG_INFO(0, pairs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_msetnx, 0, 0, 1)
    ZEND_ARG_INFO(0, pairs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_multi, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_persist, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pexpire, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timestamp)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pexpireAt, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timestamp)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pfadd, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, elements)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pfcount, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pfmerge, 0, 0, 2)
    ZEND_ARG_INFO(0, dstkey)
    ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_ping, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_psetex, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, expire)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_psubscribe, 0, 0, 1)
    ZEND_ARG_INFO(0, patterns)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_punsubscribe, 0, 0, 1)
    ZEND_ARG_INFO(0, patterns)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_pttl, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_publish, 0, 0, 2)
    ZEND_ARG_INFO(0, channel)
    ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_rPop, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_rPush, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_rPushx, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_randomKey, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_renameKey, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, newkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_renameNx, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, newkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_restore, 0, 0, 3)
    ZEND_ARG_INFO(0, ttl)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_role, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_rpoplpush, 0, 0, 2)
    ZEND_ARG_INFO(0, src)
    ZEND_ARG_INFO(0, dst)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sAdd, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sContains, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sDiff, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sDiffStore, 0, 0, 2)
    ZEND_ARG_INFO(0, dst)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sInter, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sInterStore, 0, 0, 2)
    ZEND_ARG_INFO(0, dst)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sMembers, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sMove, 0, 0, 3)
    ZEND_ARG_INFO(0, src)
    ZEND_ARG_INFO(0, dst)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sPop, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sRandMember, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sRemove, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sSize, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sUnion, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_sUnionStore, 0, 0, 2)
    ZEND_ARG_INFO(0, dst)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_save, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_script, 0, 0, 1)
    ZEND_ARG_INFO(0, cmd)
    ZEND_ARG_INFO(0, args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_select, 0, 0, 1)
    ZEND_ARG_INFO(0, dbindex)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_set, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, opt)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setBit, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setTimeout, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setex, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, expire)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_setnx, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_strlen, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_subscribe, 0, 0, 1)
    ZEND_ARG_INFO(0, channels)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_unsubscribe, 0, 0, 1)
    ZEND_ARG_INFO(0, channels)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_time, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_ttl, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_type, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_unwatch, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_watch, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zAdd, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, score)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zPopMin, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zPopMax, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bzPopMin, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timeout_or_key)
    ZEND_ARG_INFO(0, extra_args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_bzPopMax, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, timeout_or_key)
    ZEND_ARG_INFO(0, extra_args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zCard, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zCount, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zDelete, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, other_members)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zDeleteRangeByRank, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zDeleteRangeByScore, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zIncrBy, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zInter, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, keys)
    ZEND_ARG_INFO(0, weights)
    ZEND_ARG_INFO(0, aggregate)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, scores)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRangeByLex, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRangeByScore, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRank, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRevRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, scores)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRevRangeByLex, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRevRangeByScore, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRevRank, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zScore, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zUnion, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, keys)
    ZEND_ARG_INFO(0, weights)
    ZEND_ARG_INFO(0, aggregate)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_del, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, other_keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lLen, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lrange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_lrem, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_ltrim, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, stop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_mget, 0, 0, 1)
    ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_rename, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, newkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_scard, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRem, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, other_members)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRemRangeByRank, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRemRangeByScore, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, min)
    ZEND_ARG_INFO(0, max)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zRemove, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, member)
    ZEND_ARG_INFO(0, other_members)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zSize, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zinterstore, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, keys)
    ZEND_ARG_INFO(0, weights)
    ZEND_ARG_INFO(0, aggregate)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_zunionstore, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, keys)
    ZEND_ARG_INFO(0, weights)
    ZEND_ARG_INFO(0, aggregate)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xLen, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xAdd, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, id)
    ZEND_ARG_INFO(0, pairs)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xRead, 0, 0, 1)
    ZEND_ARG_INFO(0, streams)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xDel, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xRevRange, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, end)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xTrim, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xGroupCreate, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, id)
    ZEND_ARG_INFO(0, mkstream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xGroupSetId, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xGroupDestroy, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xGroupCreateConsumer, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, consumer_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xGroupDelConsumer, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, consumer_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xReadGroup, 0, 0, 3)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, consumer_name)
    ZEND_ARG_INFO(0, streams)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xPending, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xAck, 0, 0, 3)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xClaim, 0, 0, 5)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, consumer_name)
    ZEND_ARG_INFO(0, min_idle_time)
    ZEND_ARG_INFO(0, id)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xAutoClaim, 0, 0, 5)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
    ZEND_ARG_INFO(0, consumer_name)
    ZEND_ARG_INFO(0, min_idle_time)
    ZEND_ARG_INFO(0, start)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xInfoConsumers, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xInfoGroups, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_coro_xInfoStream, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()
// clang-format on

#define IS_EX_PX_ARG(a) (IS_EX_ARG(a) || IS_PX_ARG(a))
#define IS_NX_XX_ARG(a) (IS_NX_ARG(a) || IS_XX_ARG(a))

struct RedisClient {
    redisContext *context;
    struct {
        bool auth;
        long db_num;
        bool subscribe;
    } session;
    double connect_timeout;
    double timeout;
    bool serialize;
    bool defer;
    uint8_t reconnect_interval;
    uint8_t reconnected_count;
    bool auth;
    bool compatibility_mode;
    long database;
    zval *zobject;
    zval _zobject;
    zend_object std;
};

#define SW_REDIS_COMMAND_CHECK                                                                                         \
    Coroutine::get_current_safe();                                                                                     \
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);

#define SW_REDIS_COMMAND_ARGV_FILL(str, str_len)                                                                       \
    argvlen[i] = str_len;                                                                                              \
    argv[i] = estrndup(str, str_len);                                                                                  \
    i++;

#define SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(_val)                                                                \
    if (redis->serialize) {                                                                                            \
        smart_str sstr = {};                                                                                           \
        php_serialize_data_t s_ht;                                                                                     \
        PHP_VAR_SERIALIZE_INIT(s_ht);                                                                                  \
        php_var_serialize(&sstr, _val, &s_ht);                                                                         \
        argvlen[i] = (size_t) sstr.s->len;                                                                             \
        argv[i] = estrndup(sstr.s->val, sstr.s->len);                                                                  \
        zend_string_release(sstr.s);                                                                                   \
        PHP_VAR_SERIALIZE_DESTROY(s_ht);                                                                               \
    } else {                                                                                                           \
        zend_string *convert_str = zval_get_string(_val);                                                              \
        argvlen[i] = ZSTR_LEN(convert_str);                                                                            \
        argv[i] = estrndup(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str));                                              \
        zend_string_release(convert_str);                                                                              \
    }                                                                                                                  \
    i++;

#define SW_REDIS_COMMAND_ALLOC_ARGV                                                                                    \
    size_t stack_argvlen[SW_REDIS_COMMAND_BUFFER_SIZE];                                                                \
    char *stack_argv[SW_REDIS_COMMAND_BUFFER_SIZE];                                                                    \
    size_t *argvlen;                                                                                                   \
    char **argv;                                                                                                       \
    if (argc > SW_REDIS_COMMAND_BUFFER_SIZE) {                                                                         \
        argvlen = (size_t *) emalloc(sizeof(size_t) * (argc));                                                         \
        argv = (char **) emalloc(sizeof(char *) * (argc));                                                             \
    } else {                                                                                                           \
        argvlen = stack_argvlen;                                                                                       \
        argv = stack_argv;                                                                                             \
    }

#define SW_REDIS_COMMAND_INCREASE_ARGV(_new_argc)                                                                      \
    if (_new_argc > SW_REDIS_COMMAND_BUFFER_SIZE && _new_argc > argc) {                                                \
        size_t *tmp_argvlen;                                                                                           \
        char **tmp_argv;                                                                                               \
        tmp_argvlen = (size_t *) emalloc(sizeof(size_t) * (_new_argc));                                                \
        tmp_argv = (char **) emalloc(sizeof(char *) * (_new_argc));                                                    \
        for (int argc_i = 0; argc_i < argc; argc_i++) {                                                                \
            tmp_argvlen[argc_i] = argvlen[argc_i];                                                                     \
            tmp_argv[argc_i] = argv[argc_i];                                                                           \
        }                                                                                                              \
        argvlen = tmp_argvlen;                                                                                         \
        argv = tmp_argv;                                                                                               \
    }                                                                                                                  \
    argc = _new_argc;

#define SW_REDIS_COMMAND_FREE_ARGV                                                                                     \
    if (argv != stack_argv) {                                                                                          \
        efree(argvlen);                                                                                                \
        efree(argv);                                                                                                   \
    }

enum { SW_REDIS_MODE_MULTI, SW_REDIS_MODE_PIPELINE };

static void swoole_redis_coro_parse_result(RedisClient *redis, zval *return_value, redisReply *reply);

static sw_inline RedisClient *php_swoole_redis_coro_fetch_object(zend_object *obj) {
    return (RedisClient *) ((char *) obj - swoole_redis_coro_handlers.offset);
}

static sw_inline RedisClient *php_swoole_get_redis_client(zval *zobject) {
    RedisClient *redis = (RedisClient *) php_swoole_redis_coro_fetch_object(Z_OBJ_P(zobject));
    if (UNEXPECTED(!redis)) {
        php_swoole_fatal_error(E_ERROR, "you must call Redis constructor first");
    }
    return redis;
}

static sw_inline Socket *swoole_redis_coro_get_socket(redisContext *context) {
    if (context->fd > 0 && SwooleTG.reactor) {
        return swoole_coroutine_get_socket_object(context->fd);
    }
    return nullptr;
}

static sw_inline bool swoole_redis_coro_close(RedisClient *redis) {
    if (redis->context) {
        int sockfd = redis->context->fd;
        Socket *socket = swoole_redis_coro_get_socket(redis->context);
        swoole_trace_log(SW_TRACE_REDIS_CLIENT, "redis connection closed, fd=%d", sockfd);
        zend_update_property_bool(swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("connected"), 0);
        if (!(socket && socket->has_bound())) {
            redisFreeKeepFd(redis->context);
            redis->context = nullptr;
            redis->session = {false, 0, false};
        }
        if (socket) {
            swoole_coroutine_close(sockfd);
        }
        return true;
    }
    return false;
}

static void php_swoole_redis_coro_free_object(zend_object *object) {
    RedisClient *redis = php_swoole_redis_coro_fetch_object(object);

    if (redis && redis->context) {
        swoole_redis_coro_close(redis);
    }

    zend_object_std_dtor(&redis->std);
}

static zend_object *php_swoole_redis_coro_create_object(zend_class_entry *ce) {
    RedisClient *redis = (RedisClient *) zend_object_alloc(sizeof(RedisClient), ce);
    zend_object_std_init(&redis->std, ce);
    object_properties_init(&redis->std, ce);
    redis->std.handlers = &swoole_redis_coro_handlers;
    return &redis->std;
}

static sw_inline int sw_redis_convert_err(int err) {
    switch (err) {
    case SW_REDIS_ERR_IO:
        return errno;
    case SW_REDIS_ERR_EOF:
    case SW_REDIS_ERR_CLOSED:
        return ECONNRESET;
    case SW_REDIS_ERR_OTHER:
        return EINVAL;
    case SW_REDIS_ERR_OOM:
    case SW_REDIS_ERR_ALLOC:
        return ENOMEM;
    case SW_REDIS_ERR_PROTOCOL:
        return EPROTO;
    case SW_REDIS_ERR_NOAUTH:
        return EACCES;
    case 0:
        return 0;
    default:
        return errno;
    }
}

static sw_inline void swoole_redis_handle_assoc_array_result(zval *return_value, bool str2double) {
    zval *zkey, *zvalue;
    zval zret;
    bool is_key = false;

    array_init(&zret);
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(return_value), zvalue) {
        if ((is_key = !is_key)) {
            zkey = zvalue;
        } else {
            if (str2double) {
                convert_to_double(zvalue);
            } else {
                Z_ADDREF_P(zvalue);
            }
            add_assoc_zval_ex(&zret, Z_STRVAL_P(zkey), Z_STRLEN_P(zkey), zvalue);
        }
    }
    ZEND_HASH_FOREACH_END();

    zval_ptr_dtor(return_value);
    RETVAL_ZVAL(&zret, 1, 1);
}

static bool redis_auth(RedisClient *redis, char *pw, size_t pw_len);
static bool redis_select_db(RedisClient *redis, long db_number);
static void redis_request(
    RedisClient *redis, int argc, char **argv, size_t *argvlen, zval *return_value, bool retry = false);

static bool swoole_redis_coro_connect(RedisClient *redis) {
    zval *zobject = redis->zobject;
    redisContext *context;
    Socket *socket;
    struct timeval tv;
    zval *ztmp;
    zval *zhost = sw_zend_read_property_ex(swoole_redis_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HOST), 0);
    zval *zport = sw_zend_read_property_ex(swoole_redis_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_PORT), 0);
    zend::String host(zhost);
    zend_long port = zval_get_long(zport);

    if (host.len() == 0) {
        php_swoole_fatal_error(E_WARNING, "The host is empty");
        return false;
    }

    if (redis->context) {
        context = redis->context;
        if (context->connection_type == REDIS_CONN_TCP && strcmp(context->tcp.host, host.val()) == 0 &&
            context->tcp.port == port) {
            return true;
        } else if (context->connection_type == REDIS_CONN_UNIX &&
                   (strstr(host.val(), context->unix_sock.path) - host.val()) + strlen(context->unix_sock.path) ==
                       host.len()) {
            return true;
        } else {
            swoole_redis_coro_close(redis);
        }
    }

    php_swoole_check_reactor();

    if (redis->connect_timeout > 0) {
        tv.tv_sec = redis->connect_timeout;
        tv.tv_usec = (redis->connect_timeout - (double) tv.tv_sec) * 1000 * 1000;
    }
    if (SW_STRCASECT(host.val(), host.len(), "unix:/")) {
        context = redisConnectUnixWithTimeout(host.val() + 5 + strspn(host.val() + 5, "/") - 1, tv);
    } else {
        if (port <= 0 || port > SW_CLIENT_MAX_PORT) {
            php_swoole_fatal_error(E_WARNING, "The port " ZEND_LONG_FMT " is invalid", port);
            return false;
        }
        context = redisConnectWithTimeout(host.val(), (int) port, tv);
    }

    redis->context = context;

    if (!context) {
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errType"), SW_REDIS_ERR_ALLOC);
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), sw_redis_convert_err(SW_REDIS_ERR_ALLOC));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "cannot allocate redis context");
        return false;
    }
    if (context->err) {
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errType"), context->err);
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), sw_redis_convert_err(context->err));
        zend_update_property_string(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), context->errstr);
        swoole_redis_coro_close(redis);
        return false;
    }
    if (!(socket = swoole_redis_coro_get_socket(context))) {
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "Can not found the connection");
        swoole_redis_coro_close(redis);
        return false;
    }

    socket->set_timeout(redis->timeout, Socket::TIMEOUT_RDWR);
    redis->reconnected_count = 0;
    zend_update_property_bool(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("connected"), 1);
    zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("sock"), context->fd);

    // auth and select db after connected
    zval *zsetting =
        sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, redis->zobject, ZEND_STRL("setting"), 0);
    HashTable *vht = Z_ARRVAL_P(zsetting);

    if (php_swoole_array_get_value(vht, "password", ztmp)) {
        zend::String passowrd(ztmp);
        if (passowrd.len() > 0 && !redis_auth(redis, passowrd.val(), passowrd.len())) {
            swoole_redis_coro_close(redis);
            return false;
        }
    }
    if (php_swoole_array_get_value(vht, "database", ztmp)) {
        zend_long db_number = zval_get_long(ztmp);
        // default is 0, don't need select
        if (db_number > 0 && !redis_select_db(redis, db_number)) {
            swoole_redis_coro_close(redis);
            return false;
        }
    }
    return true;
}

static sw_inline bool swoole_redis_coro_keep_liveness(RedisClient *redis) {
    Socket *socket = nullptr;
    if (!redis->context || !(socket = swoole_redis_coro_get_socket(redis->context)) || !socket->check_liveness()) {
        if (socket) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), SW_REDIS_ERR_CLOSED);
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errCode"), socket->errCode);
            zend_update_property_string(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), socket->errMsg);
        }
        swoole_redis_coro_close(redis);
        for (; redis->reconnected_count < redis->reconnect_interval; redis->reconnected_count++) {
            if (swoole_redis_coro_connect(redis)) {
                return true;
            }
        }
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), SW_REDIS_ERR_CLOSED);
        // Notice: do not update errCode
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), "connection is not available");
        return false;
    }
    return true;
}

static bool redis_auth(RedisClient *redis, char *pw, size_t pw_len) {
    int i = 0;
    size_t argvlen[2];
    char *argv[2];
    bool ret;
    zval retval;

    SW_REDIS_COMMAND_ARGV_FILL("AUTH", 4)
    SW_REDIS_COMMAND_ARGV_FILL(pw, pw_len)
    redis_request(redis, 2, argv, argvlen, &retval);
    ret = Z_BVAL_P(&retval);
    if (ret) {
        redis->session.auth = true;
    }
    return ret;
}

static bool redis_select_db(RedisClient *redis, long db_number) {
    int i = 0;
    size_t argvlen[2];
    char *argv[2];
    char str[32];
    bool ret;
    zval retval;

    SW_REDIS_COMMAND_ARGV_FILL("SELECT", 6)
    sprintf(str, "%ld", db_number);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    redis_request(redis, 2, argv, argvlen, &retval);
    ret = Z_BVAL_P(&retval);
    if (ret) {
        redis->session.db_num = db_number;
    }
    return ret;
}

static void redis_request(
    RedisClient *redis, int argc, char **argv, size_t *argvlen, zval *return_value, bool retry) {
    redisReply *reply = nullptr;
    if (!swoole_redis_coro_keep_liveness(redis)) {
        ZVAL_FALSE(return_value);
    } else {
        // must clear err before request
        redis->context->err = 0;
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), 0);
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errCode"), 0);
        zend_update_property_string(swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), "");
        if (redis->defer) {
            if (redisAppendCommandArgv(redis->context, argc, (const char **) argv, (const size_t *) argvlen) ==
                REDIS_ERR) {
                goto _error;
            } else {
                ZVAL_TRUE(return_value);
            }
        } else {
            reply =
                (redisReply *) redisCommandArgv(redis->context, argc, (const char **) argv, (const size_t *) argvlen);
            if (reply == nullptr) {
            _error:
                zend_update_property_long(
                    swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), redis->context->err);
                zend_update_property_long(swoole_redis_coro_ce,
                                          SW_Z8_OBJ_P(redis->zobject),
                                          ZEND_STRL("errCode"),
                                          sw_redis_convert_err(redis->context->err));
                zend_update_property_string(
                    swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), redis->context->errstr);
                ZVAL_FALSE(return_value);
                swoole_redis_coro_close(redis);
            } else {
                // Redis Cluster
                if (reply->type == REDIS_REPLY_ERROR &&
                    (!strncmp(reply->str, "MOVED", 5) || !strcmp(reply->str, "ASK"))) {
                    char *p1, *p2;
                    // MOVED 1234 127.0.0.1:1234
                    p1 = strrchr(reply->str, ' ') + 1;  // MOVED 1234 [p1]27.0.0.1:1234
                    p2 = strrchr(p1, ':');              // MOVED 1234 [p1]27.0.0.1[p2]1234
                    *p2 = '\0';
                    int port = atoi(p2 + 1);
                    zend_update_property_string(
                        swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("host"), p1);
                    zend_update_property_long(
                        swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("port"), port);

                    if (swoole_redis_coro_connect(redis) > 0) {
                        freeReplyObject(reply);
                        redis_request(redis, argc, argv, argvlen, return_value, retry);
                        return;
                    } else {
                        ZVAL_FALSE(return_value);
                    }
                }
                // Normal Response
                else {
                    swoole_redis_coro_parse_result(redis, return_value, reply);
                }
                freeReplyObject(reply);
            }
        }
    }
    SW_LOOP_N(argc) {
        efree(argv[i]);
    }
}

static sw_inline void sw_redis_command_empty(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[1];
    char *argv[1];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    redis_request(redis, 1, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_var_key(
    INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len, int min_argc, int has_timeout) {
    long timeout;
    int argc = ZEND_NUM_ARGS();
    if (argc < min_argc) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (argc == 0 || zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }
    zend_bool single_array = 0;
    if (has_timeout == 0) {
        single_array = argc == 1 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY;
    } else {
        single_array = argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY &&
                       SW_REDIS_COMMAND_ARGS_TYPE(z_args[1]) == IS_LONG;
        timeout = SW_REDIS_COMMAND_ARGS_LVAL(z_args[1]);
    }
    if (single_array) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 1;
    } else {
        argc++;
    }

    SW_REDIS_COMMAND_ALLOC_ARGV
    int i = 0;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    char buf[32];
    size_t buf_len;
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        if (has_timeout) {
            buf_len = sw_snprintf(buf, sizeof(buf), "%ld", timeout);
            SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len);
        }
    } else {
        if (has_timeout && SW_REDIS_COMMAND_ARGS_TYPE(z_args[argc - 2]) != IS_LONG) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(redis->zobject),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), "Timeout value must be a LONG");
            efree(z_args);
            RETURN_FALSE;
        }
        int j, tail;
        tail = has_timeout ? argc - 2 : argc - 1;
        for (j = 0; j < tail; ++j) {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
            zend_string_release(convert_str);
        }
        if (has_timeout) {
            buf_len = sw_snprintf(buf, sizeof(buf), ZEND_LONG_FMT, SW_REDIS_COMMAND_ARGS_LVAL(z_args[tail]));
            SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len);
        }
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
}

static inline void sw_redis_command_key(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[2];
    char *argv[2];
    int argc = 2;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode) {
        if (ZVAL_IS_ARRAY(return_value) && sw_mem_equal(ZEND_STRL("HGETALL"), cmd, cmd_len)) {
            swoole_redis_handle_assoc_array_result(return_value, false);
        } else if (ZVAL_IS_NULL(return_value) && sw_mem_equal(ZEND_STRL("GET"), cmd, cmd_len)) {
            RETURN_FALSE;
        }
    }
}

static sw_inline void sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    int argc = ZEND_NUM_ARGS();
    // We at least need a key and one value
    if (argc < 2) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    // Make sure we at least have a key, and we can get other args
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }

    int i = 0, j;
    argc++;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    zend_string *convert_str = zval_get_string(&z_args[0]);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    for (j = 1; j < argc - 1; ++j) {
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(SW_REDIS_COMMAND_ARGS_REF(z_args[j]))
    }
    efree(z_args);
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    long l_val;
    zval *z_value;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "slz", &key, &key_len, &l_val, &z_value) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    int argc = 4;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_long_str(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key, *val;
    size_t key_len, val_len;
    long l_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sls", &key, &key_len, &l_val, &val, &val_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    int argc = 4;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL(val, val_len)
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_long(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    long l_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &key, &key_len, &l_val) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    int argc = 3;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    long l1_val, l2_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &key, &key_len, &l1_val, &l2_val) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    int argc = 4;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%ld", l1_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    sprintf(str, "%ld", l2_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_dbl(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    double d_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sd", &key, &key_len, &d_val) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    int argc = 3;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%f", d_val);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_key(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key1, *key2;
    size_t key1_len, key2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key1, &key1_len, &key2, &key2_len) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    int argc = 3;
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
    SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
    redis_request(redis, argc, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_val(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key;
    size_t key_len;
    zval *z_value;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &key, &key_len, &z_value) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    redis_request(redis, 3, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_NULL(return_value) && strncmp("ZRANK", cmd, cmd_len) == 0) {
        RETURN_FALSE;
    }
}

static sw_inline void sw_redis_command_key_str(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key, *val;
    size_t key_len, val_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &val, &val_len) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(val, val_len)
    redis_request(redis, 3, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key, *val1, *val2;
    size_t key_len, val1_len, val2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &val1, &val1_len, &val2, &val2_len) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(val1, val1_len)
    SW_REDIS_COMMAND_ARGV_FILL(val2, val2_len)
    redis_request(redis, 4, argv, argvlen, return_value);
}

static sw_inline void sw_redis_command_xrange(INTERNAL_FUNCTION_PARAMETERS, const char *cmd, int cmd_len) {
    char *key, *val1, *val2;
    size_t key_len, val1_len, val2_len;
    zend_long count = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|l", &key, &key_len, &val1, &val1_len, &val2, &val2_len, &count) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc;
    argc = ZEND_NUM_ARGS() == 4 ? 6 : 4;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL(cmd, cmd_len)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(val1, val1_len)
    SW_REDIS_COMMAND_ARGV_FILL(val2, val2_len)
    if (count > 0) {
        SW_REDIS_COMMAND_ARGV_FILL("COUNT", 5)
        char buf[32];
        size_t buf_len;
        buf_len = sprintf(buf, ZEND_LONG_FMT, count);
        SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_redis_coro, __construct);
static PHP_METHOD(swoole_redis_coro, __destruct);
static PHP_METHOD(swoole_redis_coro, connect);
static PHP_METHOD(swoole_redis_coro, getAuth);
static PHP_METHOD(swoole_redis_coro, getDBNum);
static PHP_METHOD(swoole_redis_coro, getOptions);
static PHP_METHOD(swoole_redis_coro, setOptions);
static PHP_METHOD(swoole_redis_coro, getDefer);
static PHP_METHOD(swoole_redis_coro, setDefer);
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
static PHP_METHOD(swoole_redis_coro, pfadd);
static PHP_METHOD(swoole_redis_coro, pfcount);
static PHP_METHOD(swoole_redis_coro, pfmerge);
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
static PHP_METHOD(swoole_redis_coro, zPopMin);
static PHP_METHOD(swoole_redis_coro, zPopMax);
static PHP_METHOD(swoole_redis_coro, bzPopMin);
static PHP_METHOD(swoole_redis_coro, bzPopMax);
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
static PHP_METHOD(swoole_redis_coro, unsubscribe);
static PHP_METHOD(swoole_redis_coro, pUnSubscribe);
static PHP_METHOD(swoole_redis_coro, multi);
static PHP_METHOD(swoole_redis_coro, exec);
static PHP_METHOD(swoole_redis_coro, eval);
static PHP_METHOD(swoole_redis_coro, evalSha);
static PHP_METHOD(swoole_redis_coro, script);
static PHP_METHOD(swoole_redis_coro, xLen);
static PHP_METHOD(swoole_redis_coro, xAdd);
static PHP_METHOD(swoole_redis_coro, xRead);
static PHP_METHOD(swoole_redis_coro, xDel);
static PHP_METHOD(swoole_redis_coro, xRange);
static PHP_METHOD(swoole_redis_coro, xRevRange);
static PHP_METHOD(swoole_redis_coro, xTrim);
static PHP_METHOD(swoole_redis_coro, xGroupCreate);
static PHP_METHOD(swoole_redis_coro, xGroupSetId);
static PHP_METHOD(swoole_redis_coro, xGroupDestroy);
static PHP_METHOD(swoole_redis_coro, xGroupCreateConsumer);
static PHP_METHOD(swoole_redis_coro, xGroupDelConsumer);
static PHP_METHOD(swoole_redis_coro, xReadGroup);
static PHP_METHOD(swoole_redis_coro, xPending);
static PHP_METHOD(swoole_redis_coro, xAck);
static PHP_METHOD(swoole_redis_coro, xClaim);
static PHP_METHOD(swoole_redis_coro, xAutoClaim);
static PHP_METHOD(swoole_redis_coro, xInfoConsumers);
static PHP_METHOD(swoole_redis_coro, xInfoGroups);
static PHP_METHOD(swoole_redis_coro, xInfoStream);
SW_EXTERN_C_END
/*---------------------Redis Command End------------------------*/
// clang-format off
static const zend_function_entry swoole_redis_coro_methods[] =
{
    PHP_ME(swoole_redis_coro, __construct, arginfo_swoole_redis_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, __destruct, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, connect, arginfo_swoole_redis_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getAuth, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getDBNum, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getOptions, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setOptions, arginfo_swoole_redis_coro_setOptions, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getDefer, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setDefer, arginfo_swoole_redis_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, recv, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, request, arginfo_swoole_redis_coro_request, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, close, arginfo_swoole_redis_coro_close, ZEND_ACC_PUBLIC)
    /*---------------------Redis Command------------------------*/
    PHP_ME(swoole_redis_coro, set, arginfo_swoole_redis_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setBit, arginfo_swoole_redis_coro_setBit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setEx, arginfo_swoole_redis_coro_setex, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, psetEx, arginfo_swoole_redis_coro_psetex, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lSet, arginfo_swoole_redis_coro_lSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, get, arginfo_swoole_redis_coro_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mGet, arginfo_swoole_redis_coro_mget, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, del, arginfo_swoole_redis_coro_del, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hDel, arginfo_swoole_redis_coro_hDel, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hSet, arginfo_swoole_redis_coro_hSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hMSet, arginfo_swoole_redis_coro_hMset, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hSetNx, arginfo_swoole_redis_coro_hSetNx, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, delete, del, arginfo_swoole_redis_coro_del, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mSet, arginfo_swoole_redis_coro_mset, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, mSetNx, arginfo_swoole_redis_coro_msetnx, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getKeys, arginfo_swoole_redis_coro_getKeys, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, keys, getKeys, arginfo_swoole_redis_coro_getKeys, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, exists, arginfo_swoole_redis_coro_exists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, type, arginfo_swoole_redis_coro_type, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, strLen, arginfo_swoole_redis_coro_strlen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lPop, arginfo_swoole_redis_coro_lPop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, blPop, arginfo_swoole_redis_coro_blPop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rPop, arginfo_swoole_redis_coro_rPop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, brPop, arginfo_swoole_redis_coro_brPop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bRPopLPush, arginfo_swoole_redis_coro_brpoplpush, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lSize, arginfo_swoole_redis_coro_lSize, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lLen, lSize, arginfo_swoole_redis_coro_lLen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sSize, arginfo_swoole_redis_coro_sSize, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, scard, sSize, arginfo_swoole_redis_coro_scard, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sPop, arginfo_swoole_redis_coro_sPop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sMembers, arginfo_swoole_redis_coro_sMembers, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, sGetMembers, sMembers, arginfo_swoole_redis_coro_key, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sRandMember, arginfo_swoole_redis_coro_sRandMember, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, persist, arginfo_swoole_redis_coro_persist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, ttl, arginfo_swoole_redis_coro_ttl, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pttl, arginfo_swoole_redis_coro_pttl, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zCard, arginfo_swoole_redis_coro_zCard, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zSize, zCard, arginfo_swoole_redis_coro_zSize, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hLen, arginfo_swoole_redis_coro_hLen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hKeys, arginfo_swoole_redis_coro_hKeys, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hVals, arginfo_swoole_redis_coro_hVals, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hGetAll, arginfo_swoole_redis_coro_hGetAll, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, debug, arginfo_swoole_redis_coro_debug, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, restore, arginfo_swoole_redis_coro_restore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, dump, arginfo_swoole_redis_coro_dump, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, renameKey, arginfo_swoole_redis_coro_renameKey, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, rename, renameKey, arginfo_swoole_redis_coro_rename, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, renameNx, arginfo_swoole_redis_coro_renameNx, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rpoplpush, arginfo_swoole_redis_coro_rpoplpush, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, randomKey, arginfo_swoole_redis_coro_randomKey, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pfadd, arginfo_swoole_redis_coro_pfadd, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pfcount, arginfo_swoole_redis_coro_pfcount, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pfmerge, arginfo_swoole_redis_coro_pfmerge, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, ping, arginfo_swoole_redis_coro_ping, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, auth, arginfo_swoole_redis_coro_auth, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, unwatch, arginfo_swoole_redis_coro_unwatch, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, watch, arginfo_swoole_redis_coro_watch, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, save, arginfo_swoole_redis_coro_save, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bgSave, arginfo_swoole_redis_coro_bgSave, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lastSave, arginfo_swoole_redis_coro_lastSave, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, flushDB, arginfo_swoole_redis_coro_flushDB, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, flushAll, arginfo_swoole_redis_coro_flushAll, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, dbSize, arginfo_swoole_redis_coro_dbSize, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bgrewriteaof, arginfo_swoole_redis_coro_bgrewriteaof, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, time, arginfo_swoole_redis_coro_time, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, role, arginfo_swoole_redis_coro_role, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setRange, arginfo_swoole_redis_coro_setRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setNx, arginfo_swoole_redis_coro_setnx, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getSet, arginfo_swoole_redis_coro_getSet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, append, arginfo_swoole_redis_coro_append, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lPushx, arginfo_swoole_redis_coro_lPushx, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lPush, arginfo_swoole_redis_coro_lPush, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rPush, arginfo_swoole_redis_coro_rPush, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, rPushx, arginfo_swoole_redis_coro_rPushx, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sContains, arginfo_swoole_redis_coro_sContains, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, sismember, sContains, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zScore, arginfo_swoole_redis_coro_zScore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRank, arginfo_swoole_redis_coro_zRank, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRevRank, arginfo_swoole_redis_coro_zRevRank, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hGet, arginfo_swoole_redis_coro_hGet, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hMGet, arginfo_swoole_redis_coro_hMget, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hExists, arginfo_swoole_redis_coro_hExists, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, publish, arginfo_swoole_redis_coro_publish, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zIncrBy, arginfo_swoole_redis_coro_zIncrBy, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zAdd, arginfo_swoole_redis_coro_zAdd, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zPopMin, arginfo_swoole_redis_coro_zPopMin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zPopMax, arginfo_swoole_redis_coro_zPopMax, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bzPopMin, arginfo_swoole_redis_coro_bzPopMin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bzPopMax, arginfo_swoole_redis_coro_bzPopMax, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zDeleteRangeByScore, arginfo_swoole_redis_coro_zDeleteRangeByScore, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemRangeByScore, zDeleteRangeByScore, arginfo_swoole_redis_coro_zRemRangeByScore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zCount, arginfo_swoole_redis_coro_zCount, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRange, arginfo_swoole_redis_coro_zRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRevRange, arginfo_swoole_redis_coro_zRevRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRangeByScore, arginfo_swoole_redis_coro_zRangeByScore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRevRangeByScore, arginfo_swoole_redis_coro_zRevRangeByScore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRangeByLex, arginfo_swoole_redis_coro_zRangeByLex, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zRevRangeByLex, arginfo_swoole_redis_coro_zRevRangeByLex, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zInter, arginfo_swoole_redis_coro_zInter, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zinterstore, zInter, arginfo_swoole_redis_coro_zinterstore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zUnion, arginfo_swoole_redis_coro_zUnion, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zunionstore, zUnion, arginfo_swoole_redis_coro_zunionstore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, incrBy, arginfo_swoole_redis_coro_incrBy, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hIncrBy, arginfo_swoole_redis_coro_hIncrBy, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, incr, arginfo_swoole_redis_coro_incr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, decrBy, arginfo_swoole_redis_coro_decrBy, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, decr, arginfo_swoole_redis_coro_decr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getBit, arginfo_swoole_redis_coro_getBit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lInsert, arginfo_swoole_redis_coro_lInsert, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lGet, arginfo_swoole_redis_coro_lGet, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lIndex, lGet, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setTimeout, arginfo_swoole_redis_coro_setTimeout, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, expire, setTimeout, arginfo_swoole_redis_coro_key_long, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pexpire, arginfo_swoole_redis_coro_pexpire, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, expireAt, arginfo_swoole_redis_coro_expireAt, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pexpireAt, arginfo_swoole_redis_coro_pexpireAt, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, move, arginfo_swoole_redis_coro_move, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, select, arginfo_swoole_redis_coro_select, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getRange, arginfo_swoole_redis_coro_getRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, listTrim, arginfo_swoole_redis_coro_listTrim, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, ltrim, listTrim, arginfo_swoole_redis_coro_ltrim, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lGetRange, arginfo_swoole_redis_coro_lGetRange, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lRange, lGetRange, arginfo_swoole_redis_coro_lrange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, lRem, arginfo_swoole_redis_coro_lrem, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, lRemove,lRem, arginfo_swoole_redis_coro_lRemove, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zDeleteRangeByRank, arginfo_swoole_redis_coro_zDeleteRangeByRank, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemRangeByRank, zDeleteRangeByRank, arginfo_swoole_redis_coro_zRemRangeByRank, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, incrByFloat, arginfo_swoole_redis_coro_incrByFloat, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, hIncrByFloat, arginfo_swoole_redis_coro_hIncrByFloat, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bitCount, arginfo_swoole_redis_coro_bitcount, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, bitOp, arginfo_swoole_redis_coro_bitop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sAdd, arginfo_swoole_redis_coro_sAdd, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sMove, arginfo_swoole_redis_coro_sMove, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sDiff, arginfo_swoole_redis_coro_sDiff, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sDiffStore, arginfo_swoole_redis_coro_sDiffStore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sUnion, arginfo_swoole_redis_coro_sUnion, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sUnionStore, arginfo_swoole_redis_coro_sUnionStore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sInter, arginfo_swoole_redis_coro_sInter, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sInterStore, arginfo_swoole_redis_coro_sInterStore, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, sRemove, arginfo_swoole_redis_coro_sRemove, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, srem, sRemove, arginfo_swoole_redis_coro_key_value, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, zDelete, arginfo_swoole_redis_coro_zDelete, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRemove, zDelete, arginfo_swoole_redis_coro_zRemove, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_redis_coro, zRem, zDelete, arginfo_swoole_redis_coro_zRem, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pSubscribe, arginfo_swoole_redis_coro_psubscribe, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, subscribe, arginfo_swoole_redis_coro_subscribe, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, unsubscribe, arginfo_swoole_redis_coro_unsubscribe, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, pUnSubscribe, arginfo_swoole_redis_coro_punsubscribe, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, multi, arginfo_swoole_redis_coro_multi, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, exec, arginfo_swoole_redis_coro_exec, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, eval, arginfo_swoole_redis_coro_eval, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, evalSha, arginfo_swoole_redis_coro_evalsha, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, script, arginfo_swoole_redis_coro_script, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xLen, arginfo_swoole_redis_coro_xLen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xAdd, arginfo_swoole_redis_coro_xAdd, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xRead, arginfo_swoole_redis_coro_xRead, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xDel, arginfo_swoole_redis_coro_xDel, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xRange, arginfo_swoole_redis_coro_xRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xRevRange, arginfo_swoole_redis_coro_xRevRange, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xTrim, arginfo_swoole_redis_coro_xTrim, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xGroupCreate, arginfo_swoole_redis_coro_xGroupCreate, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xGroupSetId, arginfo_swoole_redis_coro_xGroupSetId, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xGroupDestroy, arginfo_swoole_redis_coro_xGroupDestroy, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xGroupCreateConsumer, arginfo_swoole_redis_coro_xGroupCreateConsumer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xGroupDelConsumer, arginfo_swoole_redis_coro_xGroupDelConsumer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xReadGroup, arginfo_swoole_redis_coro_xReadGroup, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xPending, arginfo_swoole_redis_coro_xPending, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xAck, arginfo_swoole_redis_coro_xAck, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xClaim, arginfo_swoole_redis_coro_xClaim, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xAutoClaim, arginfo_swoole_redis_coro_xAutoClaim, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xInfoConsumers, arginfo_swoole_redis_coro_xInfoConsumers, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xInfoGroups, arginfo_swoole_redis_coro_xInfoGroups, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, xInfoStream, arginfo_swoole_redis_coro_xInfoStream, ZEND_ACC_PUBLIC)
    /*---------------------Redis Command End------------------------*/
    PHP_FE_END
};
// clang-format on

void php_swoole_redis_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_redis_coro, "Swoole\\Coroutine\\Redis", nullptr, "Co\\Redis", swoole_redis_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_redis_coro);
    SW_SET_CLASS_CLONEABLE(swoole_redis_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_redis_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_redis_coro);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_redis_coro, php_swoole_redis_coro_create_object, php_swoole_redis_coro_free_object, RedisClient, std);
#if PHP_VERSION_ID >= 80200
	zend_add_parameter_attribute((zend_function *) zend_hash_str_find_ptr(&swoole_redis_coro_ce->function_table, SW_STRL("auth")), 0, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);
#endif

    zend_declare_property_string(swoole_redis_coro_ce, ZEND_STRL("host"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_redis_coro_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_redis_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_redis_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_redis_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_redis_coro_ce, ZEND_STRL("errType"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_redis_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_redis_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_MULTI", SW_REDIS_MODE_MULTI);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_PIPELINE", SW_REDIS_MODE_PIPELINE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_NOT_FOUND", SW_REDIS_TYPE_NOT_FOUND);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_STRING", SW_REDIS_TYPE_STRING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_SET", SW_REDIS_TYPE_SET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_LIST", SW_REDIS_TYPE_LIST);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_ZSET", SW_REDIS_TYPE_ZSET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_HASH", SW_REDIS_TYPE_HASH);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_IO", SW_REDIS_ERR_IO);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_OTHER", SW_REDIS_ERR_OTHER);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_EOF", SW_REDIS_ERR_EOF);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_PROTOCOL", SW_REDIS_ERR_PROTOCOL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_OOM", SW_REDIS_ERR_OOM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_CLOSED", SW_REDIS_ERR_CLOSED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_NOAUTH", SW_REDIS_ERR_NOAUTH);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_REDIS_ERR_ALLOC", SW_REDIS_ERR_ALLOC);
}

static void swoole_redis_coro_set_options(RedisClient *redis, zval *zoptions, bool backward_compatibility = false) {
    zval *zsettings =
        sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, redis->zobject, ZEND_STRL("setting"), 0);
    HashTable *vht = Z_ARRVAL_P(zoptions);
    zval *ztmp;

    php_array_merge(Z_ARRVAL_P(zsettings), vht);

    if (php_swoole_array_get_value(vht, "connect_timeout", ztmp)) {
        redis->connect_timeout = zval_get_double(ztmp);
        if (redis->connect_timeout <= 0) {
            redis->connect_timeout = SW_TIMER_MAX_SEC;
        }
    }
    if (php_swoole_array_get_value(vht, "timeout", ztmp)) {
        redis->timeout = zval_get_double(ztmp);
        if (backward_compatibility) {
            redis->connect_timeout = redis->timeout;
            if (redis->connect_timeout <= 0) {
                redis->connect_timeout = SW_TIMER_MAX_SEC;
            }
        }
        if (redis->context) {
            Socket *socket = swoole_redis_coro_get_socket(redis->context);
            if (socket) {
                socket->set_timeout(redis->timeout, Socket::TIMEOUT_RDWR);
            }
        }
    }
    if (php_swoole_array_get_value(vht, "serialize", ztmp)) {
        redis->serialize = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "reconnect", ztmp)) {
        redis->reconnect_interval = (uint8_t) SW_MIN(zval_get_long(ztmp), UINT8_MAX);
    }
    if (php_swoole_array_get_value(vht, "compatibility_mode", ztmp)) {
        redis->compatibility_mode = zval_is_true(ztmp);
    }
}

static PHP_METHOD(swoole_redis_coro, __construct) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    zval *zsettings = sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    zval *zset = nullptr;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (redis->zobject) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    redis->zobject = &redis->_zobject;
    redis->_zobject = *ZEND_THIS;

    redis->connect_timeout = network::Socket::default_connect_timeout;
    redis->timeout = network::Socket::default_read_timeout;
    redis->reconnect_interval = 1;

    // settings init
    add_assoc_double(zsettings, "connect_timeout", redis->connect_timeout);
    add_assoc_double(zsettings, "timeout", redis->timeout);
    add_assoc_bool(zsettings, "serialize", redis->serialize);
    add_assoc_long(zsettings, "reconnect", redis->reconnect_interval);
    // after connected
    add_assoc_string(zsettings, "password", (char *) "");
    add_assoc_long(zsettings, "database", 0);

    if (zset) {
        swoole_redis_coro_set_options(redis, zset, true);
    }
}

static PHP_METHOD(swoole_redis_coro, connect) {
    zval *zobject = ZEND_THIS;
    char *host = nullptr;
    size_t host_len = 0;
    zend_long port = 0;
    zend_bool serialize = 0;

    SW_REDIS_COMMAND_CHECK

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lb", &host, &host_len, &port, &serialize) == FAILURE) {
        RETURN_FALSE;
    }

    zend_update_property_string(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("host"), host);
    zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("port"), port);
    redis->serialize = serialize;

    if (swoole_redis_coro_connect(redis) > 0) {
        // clear the error code only when the developer manually tries to connect successfully
        // if the kernel retries automatically, keep silent.
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errType"), 0);
        zend_update_property_long(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), 0);
        zend_update_property_string(swoole_redis_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "");
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_redis_coro, getAuth) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    if (redis->session.auth) {
        zval *ztmp = sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        if (php_swoole_array_get_value(Z_ARRVAL_P(ztmp), "password", ztmp)) {
            RETURN_ZVAL(ztmp, 1, 0);
        }
        RETURN_EMPTY_STRING();
    }
    RETURN_FALSE;
}

static PHP_METHOD(swoole_redis_coro, getDBNum) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    if (!redis->context) {
        RETURN_FALSE;
    }
    RETURN_LONG(redis->session.db_num);
}

static PHP_METHOD(swoole_redis_coro, getOptions) {
    RETURN_ZVAL(
        sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, setOptions) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    zval *zoptions;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zoptions)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_redis_coro_set_options(redis, zoptions);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_coro, getDefer) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);

    RETURN_BOOL(redis->defer);
}

static PHP_METHOD(swoole_redis_coro, setDefer) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    zend_bool defer = 1;

    if (redis->session.subscribe) {
        php_swoole_fatal_error(E_WARNING, "you should not use setDefer after subscribe");
        RETURN_FALSE;
    }
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &defer) == FAILURE) {
        RETURN_FALSE;
    }
    redis->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_coro, recv) {
    SW_REDIS_COMMAND_CHECK

    if (UNEXPECTED(!redis->context)) {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!redis->defer && !redis->session.subscribe)) {
        php_swoole_fatal_error(E_WARNING, "you should not use recv without defer or subscribe");
        RETURN_FALSE;
    }

    redisReply *reply;
_recv:
    if (redisGetReply(redis->context, (void **) &reply) == REDIS_OK) {
        swoole_redis_coro_parse_result(redis, return_value, reply);
        freeReplyObject(reply);

        if (redis->session.subscribe) {
            zval *ztype;

            if (!ZVAL_IS_ARRAY(return_value)) {
                zval_ptr_dtor(return_value);
                goto _error;
            }

            ztype = zend_hash_index_find(Z_ARRVAL_P(return_value), 0);
            if (Z_TYPE_P(ztype) == IS_STRING) {
                char *type = Z_STRVAL_P(ztype);

                if (!strcmp(type, "unsubscribe") || !strcmp(type, "punsubscribe")) {
                    zval *znum = zend_hash_index_find(Z_ARRVAL_P(return_value), 2);
                    if (Z_LVAL_P(znum) == 0) {
                        redis->session.subscribe = false;
                    }

                    return;
                } else if (!strcmp(type, "message") || !strcmp(type, "pmessage") || !strcmp(type, "subscribe") ||
                           !strcmp(type, "psubscribe")) {
                    return;
                }
            }

            zval_ptr_dtor(return_value);
            goto _recv;
        }
    } else {
    _error:
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), redis->context->err);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(redis->zobject),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(redis->context->err));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), redis->context->errstr);

        swoole_redis_coro_close(redis);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_redis_coro, close) {
    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    RETURN_BOOL(swoole_redis_coro_close(redis));
}

static PHP_METHOD(swoole_redis_coro, __destruct) {
    SW_PREVENT_USER_DESTRUCT();
}

static PHP_METHOD(swoole_redis_coro, set) {
    char *key, *exp_type = nullptr, *set_type = nullptr;
    size_t key_len, argc = 3;
    zval *z_value, *z_opts = nullptr;
    zend_long expire = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz|z", &key, &key_len, &z_value, &z_opts) == FAILURE) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK

    if (z_opts && Z_TYPE_P(z_opts) != IS_LONG && Z_TYPE_P(z_opts) != IS_ARRAY && Z_TYPE_P(z_opts) != IS_NULL) {
        RETURN_FALSE;
    }

    if (z_opts && ZVAL_IS_ARRAY(z_opts)) {
        HashTable *kt = Z_ARRVAL_P(z_opts);

        zend_string *zkey;
        zend_ulong idx;
        zval *zv;

        /* Iterate our option array */
        ZEND_HASH_FOREACH_KEY_VAL(kt, idx, zkey, zv) {
            /* Detect PX or EX argument and validate timeout */
            if (!exp_type && zkey && IS_EX_PX_ARG(ZSTR_VAL(zkey))) {
                /* Set expire type */
                exp_type = ZSTR_VAL(zkey);

                /* Try to extract timeout */
                if (Z_TYPE_P(zv) == IS_LONG) {
                    expire = Z_LVAL_P(zv);
                } else if (Z_TYPE_P(zv) == IS_STRING) {
                    expire = atol(Z_STRVAL_P(zv));
                }

                /* Expiry can't be set < 1 */
                if (expire < 1) {
                    RETURN_FALSE;
                }
                argc += 2;
            } else if (!set_type && Z_TYPE_P(zv) == IS_STRING && IS_NX_XX_ARG(Z_STRVAL_P(zv))) {
                argc += 1;
                set_type = Z_STRVAL_P(zv);
            }
            (void) idx;
        }
        ZEND_HASH_FOREACH_END();
    } else if (z_opts && Z_TYPE_P(z_opts) == IS_LONG) {
        /* Grab expiry and fail if it's < 1 */
        expire = Z_LVAL_P(z_opts);
        /* Expiry can't be set < 1 */
        if (expire < 1) {
            RETURN_FALSE;
        }
        argc += 1;
    }

    SW_REDIS_COMMAND_ALLOC_ARGV

    int i = 0;
    if (exp_type || set_type) {
        SW_REDIS_COMMAND_ARGV_FILL("SET", 3)
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)

        if (set_type) {
            SW_REDIS_COMMAND_ARGV_FILL(set_type, (size_t) strlen(set_type))
        }

        if (exp_type) {
            SW_REDIS_COMMAND_ARGV_FILL(exp_type, (size_t) strlen(exp_type))

            char str[32];
            sprintf(str, ZEND_LONG_FMT, expire);
            SW_REDIS_COMMAND_ARGV_FILL(str, (size_t) strlen(str))
        }
    } else if (expire > 0) {
        SW_REDIS_COMMAND_ARGV_FILL("SETEX", 5)
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

        char str[32];
        sprintf(str, ZEND_LONG_FMT, expire);
        SW_REDIS_COMMAND_ARGV_FILL(str, (size_t) strlen(str))

        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    } else {
        SW_REDIS_COMMAND_ARGV_FILL("SET", 3)
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_value)
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, setBit) {
    char *key;
    size_t key_len;
    long offset;
    zend_bool val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "slb", &key, &key_len, &offset, &val) == FAILURE) {
        return;
    }

    // Validate our offset
    if (offset < SW_BITOP_MIN_OFFSET || offset > SW_BITOP_MAX_OFFSET) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(swoole_redis_coro_ce,
                                    SW_Z8_OBJ_P(ZEND_THIS),
                                    ZEND_STRL("errMsg"),
                                    "Invalid OFFSET for bitop command (must be between 0-2^32-1)");
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
    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, setEx) {
    sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SETEX"));
}

static PHP_METHOD(swoole_redis_coro, psetEx) {
    sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PSETEX"));
}

static PHP_METHOD(swoole_redis_coro, lSet) {
    sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LSET"));
}

static PHP_METHOD(swoole_redis_coro, restore) {
    sw_redis_command_key_long_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RESTORE"));
}

static PHP_METHOD(swoole_redis_coro, dump) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DUMP"));
}

static PHP_METHOD(swoole_redis_coro, debug) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DEBUG"));
}

static PHP_METHOD(swoole_redis_coro, get) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("GET"));
}

static PHP_METHOD(swoole_redis_coro, mGet) {
    zval *z_args;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args) == FAILURE) {
        RETURN_FALSE;
    }
    int argc;
    argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
    if (argc == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    argc++;
    SW_REDIS_COMMAND_ALLOC_ARGV
    int i = 0;
    zval *value;
    SW_REDIS_COMMAND_ARGV_FILL("MGET", 4)
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(z_args), value)
    zend_string *convert_str = zval_get_string(value);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, hSet) {
    char *key, *field;
    size_t key_len, field_len;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &key, &key_len, &field, &field_len, &z_val) == FAILURE) {
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

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, hMSet) {
    char *key;
    size_t key_len, argc;
    zval *z_arr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len, &z_arr) == FAILURE) {
        return;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_arr))) == 0) {
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
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_arr), idx, _key, value) {
        if (_key == nullptr) {
            key_len = sw_snprintf(buf, sizeof(buf), "%ld", (long) idx);
            key = (char *) buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, hSetNx) {
    char *key, *field;
    size_t key_len, field_len;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &key, &key_len, &field, &field_len, &z_val) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    convert_to_string(z_val);
    SW_REDIS_COMMAND_ARGV_FILL("HSETNX", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(field, field_len)
    SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_val), Z_STRLEN_P(z_val))

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, hDel) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (argc < 2 || zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }
    argc++;
    int i = 0, j;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("HDEL", 4)
    for (j = 0; j < argc - 1; ++j) {
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    }
    efree(z_args);
    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, watch) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("WATCH"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, del) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DEL"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sDiff) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SDIFF"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sDiffStore) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SDIFFSTORE"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sUnion) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SUNION"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sUnionStore) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SUNIONSTORE"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sInter) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SINTER"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, sInterStore) {
    sw_redis_command_var_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SINTERSTORE"), 1, 0);
}

static PHP_METHOD(swoole_redis_coro, mSet) {
    zval *z_args;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args) == FAILURE) {
        RETURN_FALSE;
    }
    int argc;
    argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
    if (argc == 0) {
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
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_args), idx, _key, value) {
        if (_key == nullptr) {
            key_len = sw_snprintf(buf, sizeof(buf), "%ld", (long) idx);
            key = (char *) buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, mSetNx) {
    zval *z_args;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args) == FAILURE) {
        return;
    }
    int argc;
    argc = zend_hash_num_elements(Z_ARRVAL_P(z_args));
    if (argc == 0) {
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
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_args), idx, _key, value) {
        if (_key == nullptr) {
            key_len = sw_snprintf(buf, sizeof(buf), "%ld", (long) idx);
            key = (char *) buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, getKeys) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("KEYS"));
}

static PHP_METHOD(swoole_redis_coro, exists) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("EXISTS"));
}

static PHP_METHOD(swoole_redis_coro, type) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("TYPE"));
}

static PHP_METHOD(swoole_redis_coro, strLen) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("STRLEN"));
}

static PHP_METHOD(swoole_redis_coro, lPop) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LPOP"));
}

static PHP_METHOD(swoole_redis_coro, bRPopLPush) {
    char *key1, *key2;
    size_t key1_len, key2_len;
    long timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssl", &key1, &key1_len, &key2, &key2_len, &timeout) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int argc, i = 0;
    argc = timeout < 0 ? 3 : 4;
    SW_REDIS_COMMAND_ALLOC_ARGV
    if (timeout < 0) {
        SW_REDIS_COMMAND_ARGV_FILL("RPOPLPUSH", 9)
        SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
        SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
    } else {
        SW_REDIS_COMMAND_ARGV_FILL("BRPOPLPUSH", 10)
        SW_REDIS_COMMAND_ARGV_FILL(key1, key1_len)
        SW_REDIS_COMMAND_ARGV_FILL(key2, key2_len)
        char str[32];
        sprintf(str, "%ld", timeout);
        SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, blPop) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1) {
        efree(z_args);
        return;
    }

    zend_bool single_array = 0;
    if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
        single_array = 1;
    } else {
        argc += 1;
    }
    int i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("BLPOP", 5)
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    } else {
        int j;
        for (j = 0; j < argc - 1; ++j) {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
            zend_string_release(convert_str);
        }
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, brPop) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1) {
        efree(z_args);
        return;
    }

    zend_bool single_array = 0;
    if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
        single_array = 1;
    } else {
        argc += 1;
    }
    int i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("BRPOP", 5)
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    } else {
        int j;
        for (j = 0; j < argc - 1; ++j) {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
            zend_string_release(convert_str);
        }
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, rPop) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RPOP"));
}

static PHP_METHOD(swoole_redis_coro, lSize) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LLEN"));
}

static PHP_METHOD(swoole_redis_coro, sSize) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SCARD"));
}

static PHP_METHOD(swoole_redis_coro, sPop) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SPOP"));
}

static PHP_METHOD(swoole_redis_coro, sMembers) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SMEMBERS"));
}

static PHP_METHOD(swoole_redis_coro, sRandMember) {
    char *key;
    size_t key_len;
    zend_long count = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &key, &key_len, &count) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc, buf_len;
    char buf[32];
    argc = ZEND_NUM_ARGS() == 2 ? 3 : 2;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("SRANDMEMBER", 11);
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len);
    if (argc == 3) {
        buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", count);
        SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len);
    }
    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, persist) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PERSIST"));
}

static PHP_METHOD(swoole_redis_coro, ttl) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("TTL"));
}

static PHP_METHOD(swoole_redis_coro, pttl) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PTTL"));
}

static PHP_METHOD(swoole_redis_coro, zCard) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZCARD"));
}

static PHP_METHOD(swoole_redis_coro, hLen) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HLEN"));
}

static PHP_METHOD(swoole_redis_coro, hKeys) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HKEYS"));
}

static PHP_METHOD(swoole_redis_coro, hVals) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HVALS"));
}

static PHP_METHOD(swoole_redis_coro, hGetAll) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HGETALL"));
}

static PHP_METHOD(swoole_redis_coro, renameKey) {
    sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RENAME"));
}

static PHP_METHOD(swoole_redis_coro, renameNx) {
    sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RENAMENX"));
}

static PHP_METHOD(swoole_redis_coro, rpoplpush) {
    sw_redis_command_key_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RPOPLPUSH"));
}

static PHP_METHOD(swoole_redis_coro, randomKey) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RANDOMKEY"));
}

static PHP_METHOD(swoole_redis_coro, unwatch) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("UNWATCH"));
}

static PHP_METHOD(swoole_redis_coro, pfadd) {
    char *key;
    size_t key_len, argc;
    zval *z_arr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len, &z_arr) == FAILURE) {
        return;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_arr))) == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    argc = argc + 2;
    zval *value;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("PFADD", 5)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(z_arr), value) {
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str));
        zend_string_release(convert_str);
    }
    SW_HASHTABLE_FOREACH_END()

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, pfcount) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc != 1) {
        efree(z_args);
        RETURN_FALSE;
    }

    zend_bool single_array = 0;
    if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]));
        single_array = 1;
    }

    argc += 1;
    int i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("PFCOUNT", 7)
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END()
    } else {
        zend_string *convert_str = zval_get_string(&z_args[0]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, pfmerge) {
    char *key;
    size_t key_len, argc;
    zval *z_arr;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len, &z_arr) == FAILURE) {
        RETURN_FALSE;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_arr))) == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    argc = argc + 2;
    zval *value;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("PFMERGE", 7)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(z_arr), value) {
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str));
        zend_string_release(convert_str);
    }
    SW_HASHTABLE_FOREACH_END()

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, ping) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PING"));
}

static PHP_METHOD(swoole_redis_coro, auth) {
    char *pw;
    size_t pw_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &pw, &pw_len) == FAILURE) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    add_assoc_stringl(zsetting, "password", pw, pw_len);
    RETURN_BOOL(redis_auth(redis, pw, pw_len));
}

static PHP_METHOD(swoole_redis_coro, save) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SAVE"));
}

static PHP_METHOD(swoole_redis_coro, bgSave) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("BGSAVE"));
}

static PHP_METHOD(swoole_redis_coro, lastSave) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LASTSAVE"));
}

static PHP_METHOD(swoole_redis_coro, flushDB) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("FLUSHDB"));
}

static PHP_METHOD(swoole_redis_coro, flushAll) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("FLUSHALL"));
}

static PHP_METHOD(swoole_redis_coro, dbSize) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DBSIZE"));
}

static PHP_METHOD(swoole_redis_coro, bgrewriteaof) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("BGREWRITEAOF"));
}

static PHP_METHOD(swoole_redis_coro, time) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("TIME"));
}

static PHP_METHOD(swoole_redis_coro, role) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ROLE"));
}

static PHP_METHOD(swoole_redis_coro, setRange) {
    sw_redis_command_key_long_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SETRANGE"));
}

static PHP_METHOD(swoole_redis_coro, setNx) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SETNX"));
}

static PHP_METHOD(swoole_redis_coro, getSet) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("GETSET"));
}

static PHP_METHOD(swoole_redis_coro, append) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("APPEND"));
}

static PHP_METHOD(swoole_redis_coro, lPushx) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LPUSHX"));
}

static PHP_METHOD(swoole_redis_coro, lPush) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LPUSH"));
}

static PHP_METHOD(swoole_redis_coro, rPush) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RPUSH"));
}

static PHP_METHOD(swoole_redis_coro, rPushx) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("RPUSHX"));
}

static PHP_METHOD(swoole_redis_coro, sContains) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SISMEMBER"));
}

static PHP_METHOD(swoole_redis_coro, zRange) {
    char *key;
    size_t key_len;
    zend_long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc;
    argc = ZEND_NUM_ARGS() + 1;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZRANGE", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char buf[32];
    size_t buf_len;
    buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", start);
    SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
    buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", end);
    SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
    if (ws) {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    } else {
        argc = 4;
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    if (ws && redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zRevRange) {
    char *key;
    size_t key_len;
    zend_long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc;
    argc = ZEND_NUM_ARGS() + 1;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZREVRANGE", 9)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char buf[32];
    size_t buf_len;
    buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", start);
    SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
    buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", end);
    SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
    if (ws) {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    } else {
        argc = 4;
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    if (ws && redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zUnion) {
    char *key, *agg_op;
    size_t key_len;
    zval *z_keys, *z_weights = nullptr;
    HashTable *ht_keys, *ht_weights = nullptr;
    size_t argc = 2, agg_op_len = 0, keys_count;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa|a!s", &key, &key_len, &z_keys, &z_weights, &agg_op, &agg_op_len) ==
        FAILURE) {
        RETURN_FALSE;
    }

    ht_keys = Z_ARRVAL_P(z_keys);

    if ((keys_count = zend_hash_num_elements(ht_keys)) == 0) {
        RETURN_FALSE;
    } else {
        argc += keys_count + 1;
    }

    if (z_weights != nullptr) {
        ht_weights = Z_ARRVAL_P(z_weights);
        if (zend_hash_num_elements(ht_weights) != keys_count) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(ZEND_THIS),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(ZEND_THIS),
                                        ZEND_STRL("errMsg"),
                                        "WEIGHTS and keys array should be the same size!");
            RETURN_FALSE;
        }
        argc += keys_count + 1;
    }

    // AGGREGATE option
    if (agg_op_len != 0) {
        if (strncasecmp(agg_op, "SUM", sizeof("SUM")) && strncasecmp(agg_op, "MIN", sizeof("MIN")) &&
            strncasecmp(agg_op, "MAX", sizeof("MAX"))) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(ZEND_THIS),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(ZEND_THIS),
                                        ZEND_STRL("errMsg"),
                                        "Invalid AGGREGATE option provided!");
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
    buf_len = sprintf(buf, "%zu", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
    zval *value;
    SW_HASHTABLE_FOREACH_START(ht_keys, value)
    zend_string *convert_str = zval_get_string(value);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    // Weights
    if (ht_weights != nullptr) {
        SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

        SW_HASHTABLE_FOREACH_START(ht_weights, value)
        if (Z_TYPE_P(value) != IS_LONG && Z_TYPE_P(value) != IS_DOUBLE &&
            strncasecmp(Z_STRVAL_P(value), "inf", sizeof("inf")) != 0 &&
            strncasecmp(Z_STRVAL_P(value), "-inf", sizeof("-inf")) != 0 &&
            strncasecmp(Z_STRVAL_P(value), "+inf", sizeof("+inf")) != 0) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(redis->zobject),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(redis->zobject),
                                        ZEND_STRL("errMsg"),
                                        "Weights must be numeric or '-inf','inf','+inf'");
            for (j = 0; j < i; j++) {
                efree((void *) argv[j]);
            }
            SW_REDIS_COMMAND_FREE_ARGV
            RETURN_FALSE;
        }
        switch (Z_TYPE_P(value)) {
        case IS_LONG:
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(value));
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
    if (agg_op_len != 0) {
        SW_REDIS_COMMAND_ARGV_FILL("AGGREGATE", 9)
        SW_REDIS_COMMAND_ARGV_FILL(agg_op, agg_op_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zInter) {
    char *key, *agg_op;
    size_t key_len;
    zval *z_keys, *z_weights = nullptr;
    HashTable *ht_keys, *ht_weights = nullptr;
    size_t argc = 2, agg_op_len = 0, keys_count;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa|a!s", &key, &key_len, &z_keys, &z_weights, &agg_op, &agg_op_len) ==
        FAILURE) {
        RETURN_FALSE;
    }

    ht_keys = Z_ARRVAL_P(z_keys);

    if ((keys_count = zend_hash_num_elements(ht_keys)) == 0) {
        RETURN_FALSE;
    } else {
        argc += keys_count + 1;
    }

    if (z_weights != nullptr) {
        ht_weights = Z_ARRVAL_P(z_weights);
        if (zend_hash_num_elements(ht_weights) != keys_count) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(ZEND_THIS),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(ZEND_THIS),
                                        ZEND_STRL("errMsg"),
                                        "WEIGHTS and keys array should be the same size!");
            RETURN_FALSE;
        }

        argc += keys_count + 1;
    }

    // AGGREGATE option
    if (agg_op_len != 0) {
        if (strncasecmp(agg_op, "SUM", sizeof("SUM")) && strncasecmp(agg_op, "MIN", sizeof("MIN")) &&
            strncasecmp(agg_op, "MAX", sizeof("MAX"))) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(ZEND_THIS),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(ZEND_THIS),
                                        ZEND_STRL("errMsg"),
                                        "Invalid AGGREGATE option provided!");
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
    buf_len = sprintf(buf, "%zu", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
    zval *value;
    SW_HASHTABLE_FOREACH_START(ht_keys, value)
    zend_string *convert_str = zval_get_string(value);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    // Weights
    if (ht_weights != nullptr) {
        SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

        SW_HASHTABLE_FOREACH_START(ht_weights, value)
        if (Z_TYPE_P(value) != IS_LONG && Z_TYPE_P(value) != IS_DOUBLE &&
            strncasecmp(Z_STRVAL_P(value), "inf", sizeof("inf")) != 0 &&
            strncasecmp(Z_STRVAL_P(value), "-inf", sizeof("-inf")) != 0 &&
            strncasecmp(Z_STRVAL_P(value), "+inf", sizeof("+inf")) != 0) {
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(ZEND_THIS),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(SW_REDIS_ERR_OTHER));
            zend_update_property_string(swoole_redis_coro_ce,
                                        SW_Z8_OBJ_P(ZEND_THIS),
                                        ZEND_STRL("errMsg"),
                                        "Weights must be numeric or '-inf','inf','+inf'");
            for (j = 0; j < i; j++) {
                efree((void *) argv[j]);
            }
            SW_REDIS_COMMAND_FREE_ARGV
            RETURN_FALSE;
        }
        switch (Z_TYPE_P(value)) {
        case IS_LONG:
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(value));
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
    if (agg_op_len != 0) {
        SW_REDIS_COMMAND_ARGV_FILL("AGGREGATE", 9)
        SW_REDIS_COMMAND_ARGV_FILL(agg_op, agg_op_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zRangeByLex) {
    char *key, *min, *max;
    size_t key_len, min_len, max_len;
    zend_long offset = 0, count = 0;
    size_t argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if (argc != 3 && argc != 5) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(argc, "sss|ll", &key, &key_len, &min, &min_len, &max, &max_len, &offset, &count) ==
        FAILURE) {
        RETURN_FALSE;
    }

    /* min and max must start with '(' or '[', or be either '-' or '+' */
    if (min_len < 1 || max_len < 1 ||
        (min[0] != '(' && min[0] != '[' && (min[0] != '-' || min_len > 1) && (min[0] != '+' || min_len > 1)) ||
        (max[0] != '(' && max[0] != '[' && (max[0] != '-' || max_len > 1) && (max[0] != '+' || max_len > 1))) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(swoole_redis_coro_ce,
                                    SW_Z8_OBJ_P(ZEND_THIS),
                                    ZEND_STRL("errMsg"),
                                    "min and max arguments must start with '[' or '('");
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
    if (argc == 7) {
        SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
        char buf[32];
        size_t buf_len;
        buf_len = sprintf(buf, ZEND_LONG_FMT, offset);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
        buf_len = sprintf(buf, ZEND_LONG_FMT, count);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zRevRangeByLex) {
    char *key, *min, *max;
    size_t key_len, min_len, max_len;
    zend_long offset = 0, count = 0;
    int argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if (argc != 3 && argc != 5) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(argc, "sss|ll", &key, &key_len, &min, &min_len, &max, &max_len, &offset, &count) ==
        FAILURE) {
        RETURN_FALSE;
    }

    /* min and max must start with '(' or '[', or be either '-' or '+' */
    if (min_len < 1 || max_len < 1 ||
        (min[0] != '(' && min[0] != '[' && (min[0] != '-' || min_len > 1) && (min[0] != '+' || min_len > 1)) ||
        (max[0] != '(' && max[0] != '[' && (max[0] != '-' || max_len > 1) && (max[0] != '+' || max_len > 1))) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(swoole_redis_coro_ce,
                                    SW_Z8_OBJ_P(ZEND_THIS),
                                    ZEND_STRL("errMsg"),
                                    "min and max arguments must start with '[' or '('");
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
    if (argc == 7) {
        SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
        char buf[32];
        size_t buf_len;
        buf_len = sprintf(buf, ZEND_LONG_FMT, offset);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
        buf_len = sprintf(buf, ZEND_LONG_FMT, count);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zRangeByScore) {
    char *key;
    size_t key_len;
    char *start, *end;
    size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt = nullptr, *z_ele;
    zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|a", &key, &key_len, &start, &start_len, &end, &end_len, &z_opt) ==
        FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int argc = 4, i = 0;
    // Check for an options array
    if (z_opt && ZVAL_IS_ARRAY(z_opt)) {
        ht_opt = Z_ARRVAL_P(z_opt);

        // Check for WITHSCORES
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("withscores"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            withscores = 1;
            argc++;
        }

        // LIMIT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit")))) {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit, 0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && Z_TYPE_P(z_off) == IS_LONG && Z_TYPE_P(z_cnt) == IS_LONG) {
                has_limit = 1;
                limit_low = Z_LVAL_P(z_off);
                limit_high = Z_LVAL_P(z_cnt);
                argc += 3;
            }
        }
    }
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZRANGEBYSCORE", 13)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(start, start_len)
    SW_REDIS_COMMAND_ARGV_FILL(end, end_len)

    if (withscores) {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    }
    if (has_limit) {
        SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
        char buf[32];
        size_t buf_len;
        buf_len = sprintf(buf, "%ld", limit_low);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
        buf_len = sprintf(buf, "%ld", limit_high);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    if (withscores && redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zRevRangeByScore) {
    char *key;
    size_t key_len;
    char *start, *end;
    size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt = nullptr, *z_ele;
    zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|a", &key, &key_len, &start, &start_len, &end, &end_len, &z_opt) ==
        FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int argc = 4, i = 0;
    // Check for an options array
    if (z_opt && ZVAL_IS_ARRAY(z_opt)) {
        ht_opt = Z_ARRVAL_P(z_opt);

        // Check for WITHSCORES
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("withscores"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            withscores = 1;
            argc++;
        }

        // LIMIT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit")))) {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit, 0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && Z_TYPE_P(z_off) == IS_LONG && Z_TYPE_P(z_cnt) == IS_LONG) {
                has_limit = 1;
                limit_low = Z_LVAL_P(z_off);
                limit_high = Z_LVAL_P(z_cnt);
                argc += 3;
            }
        }
    }
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZREVRANGEBYSCORE", 16)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(start, start_len)
    SW_REDIS_COMMAND_ARGV_FILL(end, end_len)

    if (withscores) {
        SW_REDIS_COMMAND_ARGV_FILL("WITHSCORES", 10)
    }
    if (has_limit) {
        SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
        char buf[32];
        size_t buf_len;
        buf_len = sprintf(buf, "%ld", limit_low);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
        buf_len = sprintf(buf, "%ld", limit_high);
        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    }

    redis_request(redis, argc, argv, argvlen, return_value);

    if (withscores && redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zIncrBy) {
    char *key;
    size_t key_len;
    double incrby;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sdz", &key, &key_len, &incrby, &z_val) == FAILURE) {
        RETURN_FALSE;
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
    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, zAdd) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR

    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE) {
        efree(z_args);
        RETURN_FALSE;
    }

    if (argc > 0) {
        convert_to_string(&z_args[0]);
    }
    if (argc < 3 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING) {
        efree(z_args);
        RETURN_FALSE;
    }

    int i = 0, j, k, valid_params;
    valid_params = argc - 1;
    argc++;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZADD", 4)
    SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]),
                               (size_t) SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
    k = 1;

    if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING && IS_NX_XX_ARG(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]))) {
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]),
                                   (size_t) SW_REDIS_COMMAND_ARGS_STRLEN(z_args[k]))
        k++;
        valid_params--;
    }

    if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING &&
        strncasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]), "CH", 2) == 0) {
        SW_REDIS_COMMAND_ARGV_FILL("CH", 2)
        k++;
        valid_params--;
    }

    if (SW_REDIS_COMMAND_ARGS_TYPE(z_args[k]) == IS_STRING &&
        strncasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[k]), "INCR", 4) == 0) {
        SW_REDIS_COMMAND_ARGV_FILL("INCR", 4)
        k++;
        valid_params--;
    }

    if (valid_params % 2 != 0) {
        for (i = 0; i < 1 + k; i++) {
            efree((void *) argv[i]);
        }
        SW_REDIS_COMMAND_FREE_ARGV
        efree(z_args);
        RETURN_FALSE;
    }

    char buf[32];
    size_t buf_len;
    for (j = k; j < argc - 1; j += 2) {
        buf_len = sw_snprintf(buf, sizeof(buf), "%f", zval_get_double(&z_args[j]));
        SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(SW_REDIS_COMMAND_ARGS_REF(z_args[j + 1]))
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zPopMin) {
    char *key;
    size_t key_len;
    zend_long count = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &key, &key_len, &count) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc, buf_len;
    char buf[32];
    argc = ZEND_NUM_ARGS() == 2 ? 3 : 2;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZPOPMIN", 7);
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len);
    if (argc == 3) {
        buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", count);
        SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len);
    }
    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zPopMax) {
    char *key;
    size_t key_len;
    zend_long count = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &key, &key_len, &count) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0, argc, buf_len;
    char buf[32];
    argc = ZEND_NUM_ARGS() == 2 ? 3 : 2;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("ZPOPMAX", 7);
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len);
    if (argc == 3) {
        buf_len = sw_snprintf(buf, sizeof(buf), "%" PRId64 "", count);
        SW_REDIS_COMMAND_ARGV_FILL((char *) buf, buf_len);
    }
    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, bzPopMin) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1) {
        efree(z_args);
        return;
    }

    zend_bool single_array = 0;
    if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
        single_array = 1;
    } else {
        argc += 1;
    }
    int i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("BZPOPMIN", 8)
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    } else {
        int j;
        for (j = 0; j < argc - 1; ++j) {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
            zend_string_release(convert_str);
        }
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, bzPopMax) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 1) {
        efree(z_args);
        return;
    }

    zend_bool single_array = 0;
    if (argc == 2 && SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) == IS_ARRAY) {
        argc = zend_hash_num_elements(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0])) + 2;
        single_array = 1;
    } else {
        argc += 1;
    }
    int i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("BZPOPMAX", 8)
    if (single_array) {
        zval *value;
        SW_HASHTABLE_FOREACH_START(SW_REDIS_COMMAND_ARGS_ARRVAL(z_args[0]), value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    } else {
        int j;
        for (j = 0; j < argc - 1; ++j) {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
            zend_string_release(convert_str);
        }
    }
    efree(z_args);

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, zScore) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZSCORE"));
}

static PHP_METHOD(swoole_redis_coro, zRank) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZRANK"));
}

static PHP_METHOD(swoole_redis_coro, zRevRank) {
    sw_redis_command_key_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZREVRANK"));
}

static PHP_METHOD(swoole_redis_coro, hGet) {
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HGET"));
}

static PHP_METHOD(swoole_redis_coro, hMGet) {
    char *key;
    zval *z_arr;
    size_t argc, key_len;
    HashTable *ht_chan;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len, &z_arr) == FAILURE) {
        return;
    }

    ht_chan = Z_ARRVAL_P(z_arr);

    if ((argc = zend_hash_num_elements(ht_chan)) == 0) {
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
    zend_string *convert_str = zval_get_string(value);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();
    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        size_t index = 0;
        zval *zkey, *zvalue;
        zval zret;
        array_init(&zret);

        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(z_arr), zkey) {
            zend::String zkey_str(zkey);

            zvalue = zend_hash_index_find(Z_ARRVAL_P(return_value), index++);
            if (ZVAL_IS_NULL(zvalue)) {
                add_assoc_bool_ex(&zret, zkey_str.val(), zkey_str.len(), 0);
            } else {
                Z_ADDREF_P(zvalue);
                add_assoc_zval_ex(&zret, zkey_str.val(), zkey_str.len(), zvalue);
            }
        }
        ZEND_HASH_FOREACH_END();

        zval_ptr_dtor(return_value);
        RETVAL_ZVAL(&zret, 1, 1);
    }
}

static PHP_METHOD(swoole_redis_coro, hExists) {
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("HEXISTS"));

    RedisClient *redis = php_swoole_get_redis_client(ZEND_THIS);
    if (redis->compatibility_mode && ZVAL_IS_LONG(return_value)) {
        RETURN_BOOL(zval_get_long(return_value));
    }
}

static PHP_METHOD(swoole_redis_coro, publish) {
    sw_redis_command_key_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PUBLISH"));
}

static PHP_METHOD(swoole_redis_coro, zDeleteRangeByScore) {
    sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZREMRANGEBYSCORE"));
}

static PHP_METHOD(swoole_redis_coro, zCount) {
    sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZCOUNT"));
}

static PHP_METHOD(swoole_redis_coro, incrBy) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("INCRBY"));
}

static PHP_METHOD(swoole_redis_coro, hIncrBy) {
    char *key, *mem;
    size_t key_len, mem_len;
    long byval;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssl", &key, &key_len, &mem, &mem_len, &byval) == FAILURE) {
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

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, hIncrByFloat) {
    char *key, *mem;
    size_t key_len, mem_len;
    double byval;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssd", &key, &key_len, &mem, &mem_len, &byval) == FAILURE) {
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

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, incr) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("INCR"));
}

static PHP_METHOD(swoole_redis_coro, decrBy) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DECRBY"));
}

static PHP_METHOD(swoole_redis_coro, decr) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("DECR"));
}

static PHP_METHOD(swoole_redis_coro, getBit) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("GETBIT"));
}

static PHP_METHOD(swoole_redis_coro, lInsert) {
    char *key, *pos;
    size_t key_len, pos_len;
    zval *z_val, *z_pivot;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sszz", &key, &key_len, &pos, &pos_len, &z_pivot, &z_val) == FAILURE) {
        return;
    }

    if (strncasecmp(pos, "after", 5) && strncasecmp(pos, "before", 6)) {
        php_swoole_error(E_WARNING, "Position must be either 'BEFORE' or 'AFTER'");
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
    redis_request(redis, 5, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, lGet) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LINDEX"));
}

static PHP_METHOD(swoole_redis_coro, setTimeout) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("EXPIRE"));
}

static PHP_METHOD(swoole_redis_coro, pexpire) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PEXPIRE"));
}

static PHP_METHOD(swoole_redis_coro, expireAt) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("EXPIREAT"));
}

static PHP_METHOD(swoole_redis_coro, pexpireAt) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("PEXPIREAT"));
}

static PHP_METHOD(swoole_redis_coro, move) {
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("MOVE"));
}

static PHP_METHOD(swoole_redis_coro, select) {
    zend_long db_number;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(db_number)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_REDIS_COMMAND_CHECK
    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_redis_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    add_assoc_long(zsetting, "database", db_number);
    RETURN_BOOL(redis_select_db(redis, db_number));
}

static PHP_METHOD(swoole_redis_coro, getRange) {
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("GETRANGE"));
}

static PHP_METHOD(swoole_redis_coro, listTrim) {
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LTRIM"));
}

static PHP_METHOD(swoole_redis_coro, lGetRange) {
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("LRANGE"));
}

static PHP_METHOD(swoole_redis_coro, lRem) {
    char *key;
    size_t key_len;
    zend_long count = 0;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz|l", &key, &key_len, &z_val, &count) == FAILURE) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL("LREM", 4)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%d", (int) count);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(z_val)

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, zDeleteRangeByRank) {
    sw_redis_command_key_long_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZREMRANGEBYRANK"));
}

static PHP_METHOD(swoole_redis_coro, incrByFloat) {
    sw_redis_command_key_dbl(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("INCRBYFLOAT"));
}

static PHP_METHOD(swoole_redis_coro, bitCount) {
    char *key;
    size_t key_len;
    zend_long start = 0, end = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &key, &key_len, &start, &end) == FAILURE) {
        return;
    }

    SW_REDIS_COMMAND_CHECK

    int i = 0;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL("BITCOUNT", 8)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    char str[32];
    sprintf(str, "%d", (int) start);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))
    sprintf(str, "%d", (int) end);
    SW_REDIS_COMMAND_ARGV_FILL(str, strlen(str))

    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, bitOp) {
    int argc = ZEND_NUM_ARGS();
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || argc < 3 ||
        SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING) {
        efree(z_args);
        return;
    }

    int j, i = 0;
    argc++;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("BITOP", 5)
    SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
    for (j = 1; j < argc - 1; j++) {
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
        zend_string_release(convert_str);
    }

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
    efree(z_args);
}

static PHP_METHOD(swoole_redis_coro, sMove) {
    char *src, *dst;
    size_t src_len, dst_len;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &src, &src_len, &dst, &dst_len, &z_val) == FAILURE) {
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
    redis_request(redis, 4, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, sAdd) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SADD"));
}

static PHP_METHOD(swoole_redis_coro, sRemove) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("SREM"));
}

static PHP_METHOD(swoole_redis_coro, zDelete) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ZREM"));
}

static sw_inline void redis_subscribe(INTERNAL_FUNCTION_PARAMETERS, const char *cmd) {
    zval *z_arr;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_arr) == FAILURE) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    if (redis->defer) {
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errType"), SW_REDIS_ERR_OTHER);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(ZEND_THIS),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(SW_REDIS_ERR_OTHER));
        zend_update_property_string(swoole_redis_coro_ce,
                                    SW_Z8_OBJ_P(ZEND_THIS),
                                    ZEND_STRL("errMsg"),
                                    "subscribe cannot be used with defer enabled");
        RETURN_FALSE;
    }

    HashTable *ht_chan = Z_ARRVAL_P(z_arr);
    size_t chan_num = zend_hash_num_elements(ht_chan);
    int argc = 1 + chan_num, i = 0;
    SW_REDIS_COMMAND_ALLOC_ARGV

    SW_REDIS_COMMAND_ARGV_FILL(cmd, strlen(cmd));

    zval *value;
    SW_HASHTABLE_FOREACH_START(ht_chan, value)
    zend_string *convert_str = zval_get_string(value);
    SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str))
    zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    redis->defer = true;
    redis_request(redis, argc, argv, argvlen, return_value);
    redis->defer = false;
    SW_REDIS_COMMAND_FREE_ARGV

    if (Z_TYPE_P(return_value) == IS_TRUE) {
        redis->session.subscribe = true;
    }
}

static PHP_METHOD(swoole_redis_coro, subscribe) {
    redis_subscribe(INTERNAL_FUNCTION_PARAM_PASSTHRU, "SUBSCRIBE");
}

static PHP_METHOD(swoole_redis_coro, pSubscribe) {
    redis_subscribe(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PSUBSCRIBE");
}

static PHP_METHOD(swoole_redis_coro, unsubscribe) {
    redis_subscribe(INTERNAL_FUNCTION_PARAM_PASSTHRU, "UNSUBSCRIBE");
}

static PHP_METHOD(swoole_redis_coro, pUnSubscribe) {
    redis_subscribe(INTERNAL_FUNCTION_PARAM_PASSTHRU, "PUNSUBSCRIBE");
}

static PHP_METHOD(swoole_redis_coro, multi) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("MULTI"));
}

static PHP_METHOD(swoole_redis_coro, exec) {
    sw_redis_command_empty(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("EXEC"));
}

static PHP_METHOD(swoole_redis_coro, request) {
    SW_REDIS_COMMAND_CHECK

    zval *params = nullptr;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &params) == FAILURE) {
        RETURN_FALSE;
    }

    int argc = zend_hash_num_elements(Z_ARRVAL_P(params));
    int i = 0;
    zval *value;

    SW_REDIS_COMMAND_ALLOC_ARGV

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
    if (i == argc) {
        break;
    }
    zend_string *convert_str = zval_get_string(value);
    argvlen[i] = ZSTR_LEN(convert_str);
    argv[i] = estrndup(ZSTR_VAL(convert_str), ZSTR_LEN(convert_str));
    zend_string_release(convert_str);
    i++;
    SW_HASHTABLE_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, eval) {
    char *script;
    size_t script_len;
    zval *params = nullptr;
    zend_long keys_num = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|al", &script, &script_len, &params, &keys_num) == FAILURE) {
        RETURN_FALSE;
    }

    HashTable *params_ht = nullptr;
    uint32_t params_num = 0;
    if (params) {
        params_ht = Z_ARRVAL_P(params);
        params_num = zend_hash_num_elements(params_ht);
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t *argvlen = (size_t *) emalloc(sizeof(size_t) * (params_num + 3));
    char **argv = (char **) emalloc(sizeof(char *) * (params_num + 3));

    SW_REDIS_COMMAND_ARGV_FILL("EVAL", 4)
    SW_REDIS_COMMAND_ARGV_FILL(script, script_len)

    char keys_num_str[32] = {};
    sprintf(keys_num_str, ZEND_LONG_FMT, keys_num);
    SW_REDIS_COMMAND_ARGV_FILL(keys_num_str, strlen(keys_num_str));

    if (params_ht) {
        zval *param;
        SW_HASHTABLE_FOREACH_START(params_ht, param)
        zend_string *param_str = zval_get_string(param);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(param_str), ZSTR_LEN(param_str))
        zend_string_release(param_str);
        SW_HASHTABLE_FOREACH_END();
    }

    redis_request(redis, params_num + 3, argv, argvlen, return_value);
    efree(argvlen);
    efree(argv);
}

static PHP_METHOD(swoole_redis_coro, evalSha) {
    char *sha;
    size_t sha_len;
    zval *params = nullptr;
    long keys_num = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|al", &sha, &sha_len, &params, &keys_num) == FAILURE) {
        RETURN_FALSE;
    }

    HashTable *params_ht = nullptr;
    uint32_t params_num = 0;
    if (params) {
        params_ht = Z_ARRVAL_P(params);
        params_num = zend_hash_num_elements(params_ht);
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0;
    size_t *argvlen = (size_t *) emalloc(sizeof(size_t) * (params_num + 3));
    char **argv = (char **) emalloc(sizeof(char *) * (params_num + 3));

    SW_REDIS_COMMAND_ARGV_FILL("EVALSHA", 7)
    SW_REDIS_COMMAND_ARGV_FILL(sha, sha_len)

    char keys_num_str[32] = {};
    sprintf(keys_num_str, "%ld", keys_num);
    SW_REDIS_COMMAND_ARGV_FILL(keys_num_str, strlen(keys_num_str));

    if (params) {
        zval *param;
        SW_HASHTABLE_FOREACH_START(params_ht, param)
        zend_string *param_str = zval_get_string(param);
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(param_str), ZSTR_LEN(param_str))
        zend_string_release(param_str);
        SW_HASHTABLE_FOREACH_END();
    }

    redis_request(redis, params_num + 3, argv, argvlen, return_value);
    efree(argvlen);
    efree(argv);
}

static PHP_METHOD(swoole_redis_coro, script) {
    int argc = ZEND_NUM_ARGS();
    if (argc < 1) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGS_ARR
    if (zend_get_parameters_array(ht, argc, z_args) == FAILURE || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING) {
        efree(z_args);
        RETURN_FALSE;
    }

    int i = 0;
    if (!strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "flush") ||
        !strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "kill")) {
        size_t argvlen[2];
        char *argv[2];
        SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
        SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[0]))
        redis_request(redis, 2, argv, argvlen, return_value);
        efree(z_args);
    } else if (!strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "exists")) {
        if (argc < 2) {
            efree(z_args);
            RETURN_FALSE;
        } else {
            size_t *argvlen = (size_t *) emalloc(sizeof(size_t) * (argc + 1));
            char **argv = (char **) emalloc(sizeof(char *) * (argc + 1));
            SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
            SW_REDIS_COMMAND_ARGV_FILL("EXISTS", 6)
            int j = 1;
            for (; j < argc; j++) {
                zend_string *z_arg_str = zval_get_string(&z_args[j]);
                SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(z_arg_str), ZSTR_LEN(z_arg_str))
                zend_string_release(z_arg_str);
            }

            redis_request(redis, argc + 1, argv, argvlen, return_value);
            efree(argvlen);
            efree(argv);
            efree(z_args);
        }
    } else if (!strcasecmp(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[0]), "load")) {
        if (argc < 2 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[1]) != IS_STRING) {
            efree(z_args);
            RETURN_FALSE;
        } else {
            size_t argvlen[3];
            char *argv[3];
            SW_REDIS_COMMAND_ARGV_FILL("SCRIPT", 6)
            SW_REDIS_COMMAND_ARGV_FILL("LOAD", 4)
            SW_REDIS_COMMAND_ARGV_FILL(SW_REDIS_COMMAND_ARGS_STRVAL(z_args[1]), SW_REDIS_COMMAND_ARGS_STRLEN(z_args[1]))
            redis_request(redis, 3, argv, argvlen, return_value);
            efree(z_args);
        }
    } else {
        efree(z_args);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_redis_coro, xLen) {
    sw_redis_command_key(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("XLEN"));
}

static PHP_METHOD(swoole_redis_coro, xAdd) {
    zval *z_options = nullptr, *z_ele;
    HashTable *ht_opt, *ht_ele;
    char *key, *id;
    size_t key_len, id_len;
    zval *z_arr;
    int argc, options_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssa|a", &key, &key_len, &id, &id_len, &z_arr, &z_options) == FAILURE) {
        return;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_arr))) == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0;
    argc = argc * 2 + 3;
    zval *value;
    char buf[32];
    size_t buf_len;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XADD", 4)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        int has_maxlen_minid = 0;
        int can_limit = 0;
        // NOMKSTREAM
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("nomkstream"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL("NOMKSTREAM", 10)
            options_argc++;
        }
        // MAXLEN
        if (has_maxlen_minid == 0 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("maxlen")))) {
            has_maxlen_minid = 1;
            if (Z_TYPE_P(z_ele) == IS_LONG) {
                SW_REDIS_COMMAND_ARGV_FILL("MAXLEN", 6)
                buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
                SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                options_argc += 2;
            } else if (Z_TYPE_P(z_ele) == IS_ARRAY) {
                ht_ele = Z_ARRVAL_P(z_ele);
                zval *z_maxlen_p1 = zend_hash_index_find(ht_ele, 0);
                zval *z_maxlen_p2 = zend_hash_index_find(ht_ele, 1);
                if (Z_TYPE_P(z_maxlen_p1) == IS_STRING && Z_TYPE_P(z_maxlen_p2) == IS_LONG) {
                    char *maxlen_p1 = Z_STRVAL_P(z_maxlen_p1);
                    zend_long maxlen_p2 = Z_LVAL_P(z_maxlen_p2);
                    if ((strcmp(maxlen_p1, "=") == 0 || strcmp(maxlen_p1, "~") == 0) && maxlen_p2 >= 0) {
                        if ((strcmp(maxlen_p1, "~") == 0)) {
                            can_limit = 1;
                        }
                        SW_REDIS_COMMAND_ARGV_FILL("MAXLEN", 6)
                        SW_REDIS_COMMAND_ARGV_FILL(maxlen_p1, 1)
                        buf_len = sprintf(buf, ZEND_LONG_FMT, maxlen_p2);
                        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                        options_argc += 3;
                    }
                }
            }
        }
        // MINID
        if (has_maxlen_minid == 0 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("minid")))) {
            has_maxlen_minid = 1;
            if (Z_TYPE_P(z_ele) == IS_STRING && Z_STRLEN_P(z_ele) > 0) {
                SW_REDIS_COMMAND_ARGV_FILL("MINID", 5)
                SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_ele), Z_STRLEN_P(z_ele))
                options_argc += 2;
            } else if (Z_TYPE_P(z_ele) == IS_ARRAY) {
                ht_ele = Z_ARRVAL_P(z_ele);
                zval *z_minid_p1 = zend_hash_index_find(ht_ele, 0);
                zval *z_minid_p2 = zend_hash_index_find(ht_ele, 1);
                if (Z_TYPE_P(z_minid_p1) == IS_STRING && Z_TYPE_P(z_minid_p2) == IS_STRING) {
                    char *minid_p1 = Z_STRVAL_P(z_minid_p1);
                    char *minid_p2 = Z_STRVAL_P(z_minid_p2);
                    if ((strcmp(minid_p1, "=") == 0 || strcmp(minid_p1, "~") == 0) && strlen(minid_p2) > 0) {
                        if ((strcmp(minid_p1, "~") == 0)) {
                            can_limit = 1;
                        }
                        SW_REDIS_COMMAND_ARGV_FILL("MINID", 5)
                        SW_REDIS_COMMAND_ARGV_FILL(minid_p1, 1)
                        SW_REDIS_COMMAND_ARGV_FILL(minid_p2, strlen(minid_p2))
                        options_argc += 3;
                    }
                }
            }
        }
        // LIMIT
        if (can_limit == 1 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    // id
    SW_REDIS_COMMAND_ARGV_FILL(id, id_len)

    // k-v
    zend_ulong idx;
    zend_string *_key;
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(z_arr), idx, _key, value) {
        if (_key == nullptr) {
            key_len = sw_snprintf(buf, sizeof(buf), ZEND_LONG_FMT, idx);
            key = (char *) buf;
        } else {
            key_len = ZSTR_LEN(_key);
            key = ZSTR_VAL(_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
        SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(value)
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);
    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xRead) {
    zval *z_streams = nullptr, *z_options = nullptr, *z_ele;
    HashTable *ht_opt;
    int i = 0, argc = 0, options_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a|a", &z_streams, &z_options) == FAILURE) {
        RETURN_FALSE;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_streams))) == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK

    argc = argc * 2 + 2;
    char buf[32];
    size_t buf_len;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XREAD", 5)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        // COUNT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("count"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("COUNT", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // BLOCK
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("block"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("BLOCK", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    // streams
    SW_REDIS_COMMAND_ARGV_FILL("STREAMS", 7)
    zend_long _num_key;
    zend_string *_str_key;
    zval *_val;
    ZEND_HASH_FOREACH_KEY(Z_ARRVAL_P(z_streams), _num_key, _str_key) {
        if (_str_key == NULL) {
            _str_key = zend_long_to_str(_num_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(_str_key), ZSTR_LEN(_str_key))
    }
    ZEND_HASH_FOREACH_END();
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(z_streams), _val) {
        convert_to_string(_val);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(_val), Z_STRLEN_P(_val))
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xRange) {
    sw_redis_command_xrange(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("XRANGE"));
}

static PHP_METHOD(swoole_redis_coro, xRevRange) {
    sw_redis_command_xrange(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("XREVRANGE"));
}

static PHP_METHOD(swoole_redis_coro, xTrim) {
    zval *z_options = nullptr, *z_ele;
    HashTable *ht_opt, *ht_ele;
    int i = 0, argc = 2, options_argc = 0;
    char buf[32], *key;
    size_t buf_len, key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|a", &key, &key_len, &z_options) == FAILURE) {
        RETURN_FALSE;
    }
    if (php_swoole_array_length_safe(z_options) < 1) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XTRIM", 5)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        int has_maxlen_minid = 0;
        int can_limit = 0;
        // MAXLEN
        if (has_maxlen_minid == 0 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("maxlen")))) {
            has_maxlen_minid = 1;
            if (Z_TYPE_P(z_ele) == IS_LONG) {
                SW_REDIS_COMMAND_ARGV_FILL("MAXLEN", 6)
                buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
                SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                options_argc += 2;
            } else if (Z_TYPE_P(z_ele) == IS_ARRAY) {
                ht_ele = Z_ARRVAL_P(z_ele);
                zval *z_maxlen_p1 = zend_hash_index_find(ht_ele, 0);
                zval *z_maxlen_p2 = zend_hash_index_find(ht_ele, 1);
                if (Z_TYPE_P(z_maxlen_p1) == IS_STRING && Z_TYPE_P(z_maxlen_p2) == IS_LONG) {
                    char *maxlen_p1 = Z_STRVAL_P(z_maxlen_p1);
                    zend_long maxlen_p2 = Z_LVAL_P(z_maxlen_p2);
                    if ((strcmp(maxlen_p1, "=") == 0 || strcmp(maxlen_p1, "~") == 0) && maxlen_p2 >= 0) {
                        if ((strcmp(maxlen_p1, "~") == 0)) {
                            can_limit = 1;
                        }
                        SW_REDIS_COMMAND_ARGV_FILL("MAXLEN", 6)
                        SW_REDIS_COMMAND_ARGV_FILL(maxlen_p1, 1)
                        buf_len = sprintf(buf, ZEND_LONG_FMT, maxlen_p2);
                        SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
                        options_argc += 3;
                    }
                }
            }
        }
        // MINID
        if (has_maxlen_minid == 0 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("minid")))) {
            has_maxlen_minid = 1;
            if (Z_TYPE_P(z_ele) == IS_STRING && Z_STRLEN_P(z_ele) > 0) {
                SW_REDIS_COMMAND_ARGV_FILL("MINID", 5)
                SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_ele), Z_STRLEN_P(z_ele))
                options_argc += 2;
            } else if (Z_TYPE_P(z_ele) == IS_ARRAY) {
                ht_ele = Z_ARRVAL_P(z_ele);
                zval *z_minid_p1 = zend_hash_index_find(ht_ele, 0);
                zval *z_minid_p2 = zend_hash_index_find(ht_ele, 1);
                if (Z_TYPE_P(z_minid_p1) == IS_STRING && Z_TYPE_P(z_minid_p2) == IS_STRING) {
                    char *minid_p1 = Z_STRVAL_P(z_minid_p1);
                    char *minid_p2 = Z_STRVAL_P(z_minid_p2);
                    if ((strcmp(minid_p1, "=") == 0 || strcmp(minid_p1, "~") == 0) && strlen(minid_p2) > 0) {
                        if ((strcmp(minid_p1, "~") == 0)) {
                            can_limit = 1;
                        }
                        SW_REDIS_COMMAND_ARGV_FILL("MINID", 5)
                        SW_REDIS_COMMAND_ARGV_FILL(minid_p1, 1)
                        SW_REDIS_COMMAND_ARGV_FILL(minid_p2, strlen(minid_p2))
                        options_argc += 3;
                    }
                }
            }
        }
        // LIMIT
        if (can_limit == 1 && (z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("LIMIT", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xDel) {
    sw_redis_command_key_var_val(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("XDEL"));
}

static PHP_METHOD(swoole_redis_coro, xGroupCreate) {
    char *key, *group_name, *id;
    size_t key_len, group_name_len, id_len;
    zend_bool mkstream = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|b", &key, &key_len, &group_name, &group_name_len, &id, &id_len, &mkstream) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 5;
    size_t argvlen[6];
    char *argv[6];
    SW_REDIS_COMMAND_ARGV_FILL("XGROUP", 6)
    SW_REDIS_COMMAND_ARGV_FILL("CREATE", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(id, id_len)
    if (mkstream) {
        SW_REDIS_COMMAND_ARGV_FILL("MKSTREAM", 8)
        argc = 6;
    }

    redis_request(redis, argc, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, xGroupSetId) {
    char *key, *group_name, *id;
    size_t key_len, group_name_len, id_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &group_name, &group_name_len, &id, &id_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 5;
    size_t argvlen[5];
    char *argv[5];
    SW_REDIS_COMMAND_ARGV_FILL("XGROUP", 6)
    SW_REDIS_COMMAND_ARGV_FILL("CREATECONSUMER", 14)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(id, id_len)

    redis_request(redis, argc, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, xGroupDestroy) {
    char *key, *group_name;
    size_t key_len, group_name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &group_name, &group_name_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 4;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL("XGROUP", 6)
    SW_REDIS_COMMAND_ARGV_FILL("DESTROY", 7)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)

    redis_request(redis, argc, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, xGroupCreateConsumer) {
    char *key, *group_name, *consumer_name;
    size_t key_len, group_name_len, consumer_name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &group_name, &group_name_len, &consumer_name, &consumer_name_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 5;
    size_t argvlen[5];
    char *argv[5];
    SW_REDIS_COMMAND_ARGV_FILL("XGROUP", 6)
    SW_REDIS_COMMAND_ARGV_FILL("CREATECONSUMER", 14)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(consumer_name, consumer_name_len)

    redis_request(redis, argc, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, xGroupDelConsumer) {
    char *key, *group_name, *consumer_name;
    size_t key_len, group_name_len, consumer_name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &group_name, &group_name_len, &consumer_name, &consumer_name_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 5;
    size_t argvlen[5];
    char *argv[5];
    SW_REDIS_COMMAND_ARGV_FILL("XGROUP", 6)
    SW_REDIS_COMMAND_ARGV_FILL("DELCONSUMER", 11)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(consumer_name, consumer_name_len)

    redis_request(redis, argc, argv, argvlen, return_value);
}

static PHP_METHOD(swoole_redis_coro, xReadGroup) {
    char *group_name, *consumer_name;
    size_t group_name_len, consumer_name_len;
    zval *z_streams = nullptr, *z_options = nullptr, *z_ele;
    HashTable *ht_opt;
    int i = 0, argc = 0, options_argc = 0;
    char buf[32];
    size_t buf_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssa|a", &group_name, &group_name_len, &consumer_name, &consumer_name_len, &z_streams, &z_options) == FAILURE) {
        RETURN_FALSE;
    }
    if ((argc = zend_hash_num_elements(Z_ARRVAL_P(z_streams))) == 0) {
        RETURN_FALSE;
    }
    SW_REDIS_COMMAND_CHECK
    argc = argc * 2 + 5;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XREADGROUP", 10)
    SW_REDIS_COMMAND_ARGV_FILL("GROUP", 5)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(consumer_name, consumer_name_len)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        // COUNT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("count"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("COUNT", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // BLOCK
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("block"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("BLOCK", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // NOACK
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("noack"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL("NOACK", 5)
            options_argc++;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    // streams
    SW_REDIS_COMMAND_ARGV_FILL("STREAMS", 7)
    zend_long _num_key;
    zend_string *_str_key;
    zval *_val;
    ZEND_HASH_FOREACH_KEY(Z_ARRVAL_P(z_streams), _num_key, _str_key) {
        if (_str_key == NULL) {
            _str_key = zend_long_to_str(_num_key);
        }
        SW_REDIS_COMMAND_ARGV_FILL(ZSTR_VAL(_str_key), ZSTR_LEN(_str_key))
    }
    ZEND_HASH_FOREACH_END();
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(z_streams), _val) {
        convert_to_string(_val);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(_val), Z_STRLEN_P(_val))
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xPending) {
    char *key, *group_name;
    size_t key_len, group_name_len;
    zval *z_options = nullptr, *z_ele;
    HashTable *ht_opt;
    int i = 0, argc = 3, options_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|a", &key, &key_len, &group_name, &group_name_len, &z_options) == FAILURE) {
        RETURN_FALSE;
    }

    char buf[32];
    size_t buf_len;
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XPENDING", 8)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        // IDLE
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("idle"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("IDLE", 4)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // START
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("start"))) && Z_TYPE_P(z_ele) == IS_STRING) {
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_ele), Z_STRLEN_P(z_ele))
            options_argc++;
        }
        // END
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("end"))) && Z_TYPE_P(z_ele) == IS_STRING) {
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_ele), Z_STRLEN_P(z_ele))
            options_argc++;
        }
        // COUNT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("count"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc++;
        }
        // CONSUMER
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("consumer"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(z_ele), Z_STRLEN_P(z_ele))
            options_argc++;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xAck) {
    char *key, *group_name;
    size_t key_len, group_name_len;
    zval *z_id = nullptr;
    int i = 0, argc = 3, id_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssa", &key, &key_len, &group_name, &group_name_len, &z_id) == FAILURE) {
        RETURN_FALSE;
    }
    if ((id_argc = zend_hash_num_elements(Z_ARRVAL_P(z_id))) == 0) {
        RETURN_FALSE;
    }
    argc += id_argc;
    SW_REDIS_COMMAND_CHECK
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XACK", 4)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)

    // id
    zval *_id;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(z_id), _id) {
        convert_to_string(_id);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(_id), Z_STRLEN_P(_id))
    }
    ZEND_HASH_FOREACH_END();

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xClaim) {
    char *key, *group_name, *consumer_name;
    size_t key_len, group_name_len, consumer_name_len;
    zend_long min_idle_time = 0;
    zval *z_id = nullptr, *z_options = nullptr, *z_ele;
    HashTable *ht_opt;
    int i = 0, argc = 5, id_argc = 0, options_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sssla|a", &key, &key_len, &group_name, &group_name_len, &consumer_name, &consumer_name_len, &min_idle_time, &z_id, &z_options) == FAILURE) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    id_argc = zend_hash_num_elements(Z_ARRVAL_P(z_id));
    argc += id_argc;
    char buf[32];
    size_t buf_len;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XCLAIM", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(consumer_name, consumer_name_len)
    buf_len = sprintf(buf, ZEND_LONG_FMT, min_idle_time);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // id
    zval *_id;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(z_id), _id) {
        convert_to_string(_id);
        SW_REDIS_COMMAND_ARGV_FILL(Z_STRVAL_P(_id), Z_STRLEN_P(_id))
    }
    ZEND_HASH_FOREACH_END();

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        // IDLE
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("idle"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("IDLE", 4)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // TIME
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("time"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("TIME", 4)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // RETRYCOUNT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("retrycount"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("RETRYCOUNT", 10)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // FORCE
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("force"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL("FORCE", 5)
            options_argc++;
        }
        // JUSTID
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("justid"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL("JUSTID", 6)
            options_argc++;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xAutoClaim) {
    char *key, *group_name, *consumer_name, *start;
    size_t key_len, group_name_len, consumer_name_len, start_len;
    zend_long min_idle_time = 0;
    zval *z_options = nullptr, *z_ele;
    HashTable *ht_opt;
    int i = 0, argc = 6, options_argc = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sssls|a", &key, &key_len, &group_name, &group_name_len, &consumer_name, &consumer_name_len, &min_idle_time, &start, &start_len, &z_options) == FAILURE) {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK
    char buf[32];
    size_t buf_len;
    SW_REDIS_COMMAND_ALLOC_ARGV
    SW_REDIS_COMMAND_ARGV_FILL("XAUTOCLAIM", 10)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)
    SW_REDIS_COMMAND_ARGV_FILL(consumer_name, consumer_name_len)
    buf_len = sprintf(buf, ZEND_LONG_FMT, min_idle_time);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
    SW_REDIS_COMMAND_ARGV_FILL(start, start_len)

    // options
    if (z_options && ZVAL_IS_ARRAY(z_options)) {
        ht_opt = Z_ARRVAL_P(z_options);
        // COUNT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("count"))) && Z_TYPE_P(z_ele) == IS_LONG) {
            SW_REDIS_COMMAND_ARGV_FILL("COUNT", 5)
            buf_len = sprintf(buf, ZEND_LONG_FMT, Z_LVAL_P(z_ele));
            SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)
            options_argc += 2;
        }
        // JUSTID
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("justid"))) && Z_TYPE_P(z_ele) == IS_TRUE) {
            SW_REDIS_COMMAND_ARGV_FILL("JUSTID", 6)
            options_argc++;
        }
    }

    SW_REDIS_COMMAND_INCREASE_ARGV(argc + options_argc)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }

    SW_REDIS_COMMAND_FREE_ARGV
}

static PHP_METHOD(swoole_redis_coro, xInfoConsumers) {
    char *key, *group_name;
    size_t key_len, group_name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &group_name, &group_name_len) == FAILURE) {
        return;
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 4;
    size_t argvlen[4];
    char *argv[4];
    SW_REDIS_COMMAND_ARGV_FILL("XINFO", 5)
    SW_REDIS_COMMAND_ARGV_FILL("CONSUMERS", 9)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)
    SW_REDIS_COMMAND_ARGV_FILL(group_name, group_name_len)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }
}

static PHP_METHOD(swoole_redis_coro, xInfoGroups) {
    char *key;
    size_t key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len) == FAILURE) {
        return;
    }

    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 3;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL("XINFO", 5)
    SW_REDIS_COMMAND_ARGV_FILL("GROUPS", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }
}

static PHP_METHOD(swoole_redis_coro, xInfoStream) {
    char *key;
    size_t key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len) == FAILURE) {
        return;
    }
    SW_REDIS_COMMAND_CHECK
    int i = 0, argc = 3;
    size_t argvlen[3];
    char *argv[3];
    SW_REDIS_COMMAND_ARGV_FILL("XINFO", 5)
    SW_REDIS_COMMAND_ARGV_FILL("STREAM", 6)
    SW_REDIS_COMMAND_ARGV_FILL(key, key_len)

    redis_request(redis, argc, argv, argvlen, return_value);

    if (redis->compatibility_mode && ZVAL_IS_ARRAY(return_value)) {
        swoole_redis_handle_assoc_array_result(return_value, true);
    }
}

static void swoole_redis_coro_parse_result(RedisClient *redis, zval *return_value, redisReply *reply) {
    int j;
    zval _val, *val = &_val;

    switch (reply->type) {
    case REDIS_REPLY_INTEGER:
        ZVAL_LONG(return_value, reply->integer);
        break;

    case REDIS_REPLY_DOUBLE:
        ZVAL_DOUBLE(return_value, reply->dval);
        break;

    case REDIS_REPLY_BOOL:
        ZVAL_BOOL(return_value, reply->integer);
        break;

    case REDIS_REPLY_ERROR:
        ZVAL_FALSE(return_value);
        if (redis->context->err == 0) {
            if (strncmp(reply->str, "NOAUTH", 6) == 0) {
                redis->context->err = SW_REDIS_ERR_NOAUTH;
            } else {
                redis->context->err = SW_REDIS_ERR_OTHER;
            }
            size_t str_len = strlen(reply->str);
            memcpy(redis->context->errstr, reply->str, SW_MIN(str_len, sizeof(redis->context->errstr) - 1));
        }
        zend_update_property_long(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), redis->context->err);
        zend_update_property_long(swoole_redis_coro_ce,
                                  SW_Z8_OBJ_P(redis->zobject),
                                  ZEND_STRL("errCode"),
                                  sw_redis_convert_err(redis->context->err));
        zend_update_property_string(
            swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), redis->context->errstr);
        break;

    case REDIS_REPLY_STATUS:
        if (redis->context->err == 0) {
            if (reply->len > 0) {
                if (strncmp(reply->str, "OK", 2) == 0) {
                    ZVAL_TRUE(return_value);
                    break;
                }
                long l;
                if (strncmp(reply->str, "string", 6) == 0) {
                    l = SW_REDIS_TYPE_STRING;
                } else if (strncmp(reply->str, "set", 3) == 0) {
                    l = SW_REDIS_TYPE_SET;
                } else if (strncmp(reply->str, "list", 4) == 0) {
                    l = SW_REDIS_TYPE_LIST;
                } else if (strncmp(reply->str, "zset", 4) == 0) {
                    l = SW_REDIS_TYPE_ZSET;
                } else if (strncmp(reply->str, "hash", 4) == 0) {
                    l = SW_REDIS_TYPE_HASH;
                } else {
                    l = SW_REDIS_TYPE_NOT_FOUND;
                }
                ZVAL_LONG(return_value, l);
            } else {
                ZVAL_TRUE(return_value);
            }
        } else {
            ZVAL_FALSE(return_value);
            zend_update_property_long(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errType"), redis->context->err);
            zend_update_property_long(swoole_redis_coro_ce,
                                      SW_Z8_OBJ_P(redis->zobject),
                                      ZEND_STRL("errCode"),
                                      sw_redis_convert_err(redis->context->err));
            zend_update_property_string(
                swoole_redis_coro_ce, SW_Z8_OBJ_P(redis->zobject), ZEND_STRL("errMsg"), redis->context->errstr);
        }
        break;

    case REDIS_REPLY_STRING:
        if (redis->serialize) {
            char *reserve_str = reply->str;
            php_unserialize_data_t s_ht;
            PHP_VAR_UNSERIALIZE_INIT(s_ht);
            if (!php_var_unserialize(return_value,
                                     (const unsigned char **) &reply->str,
                                     (const unsigned char *) reply->str + reply->len,
                                     &s_ht)) {
                ZVAL_STRINGL(return_value, reply->str, reply->len);
            }
            PHP_VAR_UNSERIALIZE_DESTROY(s_ht);
            reply->str = reserve_str;
        } else {
            ZVAL_STRINGL(return_value, reply->str, reply->len);
        }
        break;

    case REDIS_REPLY_ARRAY:
        array_init(return_value);
        for (j = 0; j < (int) reply->elements; j++) {
            swoole_redis_coro_parse_result(redis, val, reply->element[j]);
            (void) add_next_index_zval(return_value, val);
        }
        break;

    case REDIS_REPLY_NIL:
    default:
        ZVAL_NULL(return_value);
        return;
    }
}
