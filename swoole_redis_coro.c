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

#define SW_REDIS_COMMAND_ALLOC_ARGS_ARR zval *z_args = emalloc(argc*sizeof(zval));
#define SW_REDIS_COMMAND_ARGS_TYPE(arg) Z_TYPE(arg)
#define SW_REDIS_COMMAND_ARGS_LVAL(arg) Z_LVAL(arg)
#define SW_REDIS_COMMAND_ARGS_DVAL(arg) Z_DVAL(arg)
#define SW_REDIS_COMMAND_ARGS_ARRVAL(arg) Z_ARRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRVAL(arg) Z_STRVAL(arg)
#define SW_REDIS_COMMAND_ARGS_STRLEN(arg) Z_STRLEN(arg)
#define SW_REDIS_COMMAND_ARGS_REF(arg) &arg

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
    SW_REDIS_ERR_CLOSED = 6, /* Closed */
    SW_REDIS_ERR_NOAUTH = 7, /* Authentication required */
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



#define IS_EX_PX_ARG(a) (IS_EX_ARG(a) || IS_PX_ARG(a))
#define IS_NX_XX_ARG(a) (IS_NX_ARG(a) || IS_XX_ARG(a))

#define SW_REDIS_COMMAND_CHECK \
    coro_check();\
    swRedisClient *redis = swoole_get_object(getThis()); \
    if (!redis)\
    {\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_CLOSED); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "connection is not available."); \
        RETURN_FALSE;\
    }\
    if (redis->iowait == SW_REDIS_CORO_STATUS_WAIT) \
    { \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for response."); \
        RETURN_FALSE; \
    } \
    if (redis->iowait == SW_REDIS_CORO_STATUS_DONE) \
    { \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for calling recv."); \
        RETURN_FALSE; \
    } \
    switch (redis->state) \
    { \
    case SWOOLE_REDIS_CORO_STATE_CONNECT: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is not connected."); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for subscribe message."); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_CLOSED: \
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client connection is closed."); \
        RETURN_FALSE; \
        break; \
    default: \
        break; \
    }\
    sw_coro_check_bind("redis client", redis->cid);

#define SW_REDIS_COMMAND_CHECK_WITH_FREE_Z_ARGS \
    coro_check();\
    swRedisClient *redis = swoole_get_object(getThis()); \
    if (!redis)\
    {\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_CLOSED); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is waiting for response."); \
        RETURN_FALSE;\
    }\
    if (redis->iowait == SW_REDIS_CORO_STATUS_WAIT) \
    { \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for response."); \
        efree(z_args); \
        RETURN_FALSE; \
    } \
    if (redis->iowait == SW_REDIS_CORO_STATUS_DONE) \
    { \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for calling recv."); \
        RETURN_FALSE; \
    } \
    switch (redis->state) \
    { \
    case SWOOLE_REDIS_CORO_STATE_CONNECT: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is not connected."); \
        efree(z_args); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE: \
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client is waiting for subscribe message."); \
        efree(z_args); \
        RETURN_FALSE; \
        break; \
    case SWOOLE_REDIS_CORO_STATE_CLOSED: \
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;\
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redis client connection is closed."); \
        efree(z_args); \
        RETURN_FALSE; \
        break; \
    default: \
        break; \
    }

#define SW_REDIS_COMMAND_YIELD \
    redis->context->err = 0; \
    redis->context->errstr = NULL; \
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), 0); \
    zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "");  \
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
        redis->cid = sw_get_current_cid();\
        php_context *context = swoole_get_property(getThis(), 0); \
        coro_save(context); \
        coro_yield(); \
    }

#define SW_REDIS_COMMAND_ARGV_FILL(str, str_len) \
    argvlen[i] = str_len; \
    argv[i] = estrndup(str, str_len); \
    i++;
#define SW_REDIS_COMMAND_ARGV_FILL_WITH_SERIALIZE(_val) \
    if (redis->serialize) { \
        smart_str sstr = {0}; \
        php_serialize_data_t s_ht; \
        PHP_VAR_SERIALIZE_INIT(s_ht); \
        php_var_serialize(&sstr, _val, &s_ht); \
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
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER); \
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed."); \
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
    zval _value;
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
static void swoole_redis_coro_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply);

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
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        if(has_timeout) {
            buf_len = snprintf(buf, sizeof(buf), "%ld", timeout);
            SW_REDIS_COMMAND_ARGV_FILL((char*)buf, buf_len);
        }
    }
    else
    {
        if(has_timeout && SW_REDIS_COMMAND_ARGS_TYPE(z_args[argc-2]) != IS_LONG) {
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "Timeout value must be a LONG");
            efree(z_args);
            RETURN_FALSE;
        }
        int j, tail;
        tail = has_timeout ? argc - 2 : argc - 1;
        for (j = 0; j < tail; ++j)
        {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
        }
        if(has_timeout) {
            buf_len = snprintf(buf, sizeof(buf), ZEND_LONG_FMT, SW_REDIS_COMMAND_ARGS_LVAL(z_args[tail]));
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
    size_t key_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len) == FAILURE)
    {
        RETURN_FALSE;
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
    zend_string *convert_str = zval_get_string(&z_args[0]);
    SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
    zend_string_release(convert_str);
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
    size_t key_len;
    long l_val;
    zval *z_value;
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "slz", &key, &key_len, &l_val, &z_value) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key_len, val_len;
    long l_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sls", &key, &key_len, &l_val, &val, &val_len)==FAILURE)
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
    size_t key_len;
    long l_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &key, &key_len, &l_val)==FAILURE)
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
    size_t key_len;
    long l1_val, l2_val;
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &key, &key_len, &l1_val, &l2_val)==FAILURE)
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
    size_t key_len;
    double d_val;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sd", &key, &key_len, &d_val) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key1_len, key2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key1, &key1_len, &key2, &key2_len) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key_len;
    zval *z_value;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &key, &key_len, &z_value) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key_len, val_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &val, &val_len) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key_len, val1_len, val2_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &val1, &val1_len, &val2, &val2_len) == FAILURE)
    {
        RETURN_FALSE;
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
    PHP_ME(swoole_redis_coro, __construct, arginfo_swoole_redis_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, __destruct, arginfo_swoole_redis_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, connect, arginfo_swoole_redis_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, setDefer, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, getDefer, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, recv, NULL, ZEND_ACC_PUBLIC)
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
    PHP_ME(swoole_redis_coro, multi, arginfo_swoole_redis_coro_multi, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, exec, arginfo_swoole_redis_coro_exec, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, eval, arginfo_swoole_redis_coro_eval, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, evalSha, arginfo_swoole_redis_coro_evalsha, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis_coro, script, arginfo_swoole_redis_coro_script, ZEND_ACC_PUBLIC)
    /*---------------------Redis Command End------------------------*/
    PHP_FE_END
};

void swoole_redis_coro_init(int module_number)
{
    INIT_CLASS_ENTRY(swoole_redis_coro_ce, "Swoole\\Coroutine\\Redis", swoole_redis_coro_methods);
    swoole_redis_coro_class_entry_ptr = zend_register_internal_class(&swoole_redis_coro_ce);
    swoole_redis_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_redis_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Redis", swoole_redis_coro_class_entry_ptr);
    }

    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("port"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_redis_coro_class_entry_ptr, ZEND_STRL("sock"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_redis_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_redis_coro_class_entry_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_redis_coro_class_entry_ptr, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);

    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_MULTI", SW_REDIS_MODE_MULTI, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_MODE_PIPELINE", SW_REDIS_MODE_PIPELINE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_NOT_FOUND", SW_REDIS_NOT_FOUND, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_STRING", SW_REDIS_STRING, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_SET", SW_REDIS_SET, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_LIST", SW_REDIS_LIST, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_ZSET", SW_REDIS_ZSET, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_REDIS_TYPE_HASH", SW_REDIS_HASH, CONST_CS | CONST_PERSISTENT);
}

static void redis_coro_close(void* context)
{
    if (context)
    {
        redisAsyncDisconnect((redisAsyncContext *) context);
    }
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
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|z", &zset) == FAILURE)
    {
        RETURN_FALSE;
    }

    swRedisClient *redis = redis_coro_create(getThis());

    if (zset && ZVAL_IS_ARRAY(zset))
    {
        php_swoole_array_separate(zset);
        zend_update_property(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset);
        zval_ptr_dtor(zset);

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
    size_t host_len;
    long port;
    zend_bool serialize = 0;

    coro_check();

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl|b", &host, &host_len, &port, &serialize) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (host_len <= 0)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "host is empty.");
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "port is invalid.");
            RETURN_FALSE;
        }
        context = redisAsyncConnect(host, (int) port);
    }

    if (context->err)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), context->err);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), context->errstr);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS_CORO))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS_CORO | SW_EVENT_READ, swoole_redis_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS_CORO | SW_EVENT_WRITE, swoole_redis_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_REDIS_CORO | SW_EVENT_ERROR, swoole_redis_coro_onError);
    }

    redisAsyncSetConnectCallback(context, swoole_redis_coro_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_coro_onClose);

    zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("sock"), context->c.fd);

    redis->context = context;
    context->ev.addRead = swoole_redis_coro_event_AddRead;
    context->ev.delRead = swoole_redis_coro_event_DelRead;
    context->ev.addWrite = swoole_redis_coro_event_AddWrite;
    context->ev.delWrite = swoole_redis_coro_event_DelWrite;
    context->ev.cleanup = swoole_redis_coro_event_Cleanup;
    context->ev.data = redis;

    zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host);
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("port"), port);

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, redis->context->c.fd, PHP_SWOOLE_FD_REDIS_CORO | SW_EVENT_WRITE) < 0)
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
    sw_current_context->coro_params = *getThis();
    if (redis->timeout > 0)
    {
        redis->timer = swTimer_add(&SwooleG.timer, (int) (redis->timeout * 1000), 0, sw_current_context, swoole_redis_coro_onTimeout);
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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &defer) == FAILURE)
    {
        RETURN_FALSE;
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

    redis->cid = sw_get_current_cid();
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

    sw_coro_check_bind("redis client", redis->cid);

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

    zend_update_property_bool(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0);
    swoole_set_object(getThis(), NULL);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swTraceLog(SW_TRACE_REDIS_CLIENT, "object_id=%d", Z_OBJ_HANDLE_P(getThis()));

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
    if (redis->state != SWOOLE_REDIS_CORO_STATE_CLOSED && redis->state != SWOOLE_REDIS_CORO_STATE_CONNECT)
    {
        swTraceLog(SW_TRACE_REDIS_CLIENT, "close connection, fd=%d", redis->context->c.fd);

        zval *retval = NULL;
        zval *zobject = getThis();
        sw_zend_call_method_with_0_params(&zobject, swoole_redis_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            zval_ptr_dtor(retval);
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
    size_t key_len, argc = 3;
    zval *z_value, *z_opts = NULL;
    long expire = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz|z", &key, &key_len, &z_value, &z_opts) == FAILURE)
    {
        RETURN_FALSE;
    }

    SW_REDIS_COMMAND_CHECK

    if (z_opts && Z_TYPE_P(z_opts) != IS_LONG && Z_TYPE_P(z_opts) != IS_ARRAY
       && Z_TYPE_P(z_opts) != IS_NULL)
    {
        RETURN_FALSE;
    }

    if (z_opts && Z_TYPE_P(z_opts) == IS_ARRAY) {
        HashTable *kt = Z_ARRVAL_P(z_opts);

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
    size_t key_len;
    long offset;
    zend_bool val;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "slb", &key, &key_len,
                             &offset, &val)==FAILURE)
    {
        return;
    }

    // Validate our offset
    if(offset < SW_BITOP_MIN_OFFSET || offset >SW_BITOP_MAX_OFFSET) {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid OFFSET for bitop command (must be between 0-2^32-1)");
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
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args) == FAILURE)
    {
        RETURN_FALSE;
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
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hSet)
{
    char *key, *field;
    size_t key_len, field_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &key, &key_len,
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
    size_t key_len, argc;
    zval *z_arr;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len,
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

    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, hSetNx)
{
    char *key, *field;
    size_t key_len, field_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &key, &key_len,
                             &field, &field_len, &z_val) == FAILURE)
    {
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
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
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
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args) == FAILURE)
    {
        RETURN_FALSE;
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

    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, mSetNx)
{
    zval *z_args;
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_args)==FAILURE)
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
    size_t key1_len, key2_len;
    long timeout;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssl", &key1, &key1_len,
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
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    }
    else
    {
        int j;
        for (j = 0; j < argc - 1; ++j)
        {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
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
            zend_string *convert_str = zval_get_string(value);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
        SW_HASHTABLE_FOREACH_END();
        zend_string *convert_str = zval_get_string(&z_args[1]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    }
    else
    {
        int j;
        for (j = 0; j < argc - 1; ++j)
        {
            zend_string *convert_str = zval_get_string(&z_args[j]);
            SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
            zend_string_release(convert_str);
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
    size_t key_len;
    long count;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &key, &key_len,
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
    size_t pw_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &pw, &pw_len) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t key_len;
    long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE)
    {
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
    size_t key_len;
    long start, end;
    zend_bool ws = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll|b", &key, &key_len, &start, &end, &ws) == FAILURE)
    {
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
    size_t key_len;
    zval *z_keys, *z_weights=NULL;
    HashTable *ht_keys, *ht_weights=NULL;
    size_t argc = 2, agg_op_len=0, keys_count;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sa|a!s", &key,
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "WEIGHTS and keys array should be the same size!");
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid AGGREGATE option provided!");
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
    buf_len = sprintf(buf, "%zd", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
    zval *value;
    SW_HASHTABLE_FOREACH_START(ht_keys, value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    // Weights
    if(ht_weights != NULL) {
        SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

        SW_HASHTABLE_FOREACH_START(ht_weights, value)
            if(Z_TYPE_P(value) != IS_LONG && Z_TYPE_P(value) != IS_DOUBLE &&
               strncasecmp(Z_STRVAL_P(value),"inf",sizeof("inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"-inf",sizeof("-inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"+inf",sizeof("+inf")) != 0)
            {
                zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
                zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), "Weights must be numeric or '-inf','inf','+inf'");
                for (j = 0; j < i; j++)
                {
                    efree((void* )argv[j]);
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
    size_t key_len;
    zval *z_keys, *z_weights=NULL;
    HashTable *ht_keys, *ht_weights=NULL;
    size_t argc = 2, agg_op_len=0, keys_count;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sa|a!s", &key,
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "WEIGHTS and keys array should be the same size!");
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Invalid AGGREGATE option provided!");
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
    buf_len = sprintf(buf, "%zd", keys_count);
    SW_REDIS_COMMAND_ARGV_FILL(buf, buf_len)

    // Process input keys
    zval *value;
    SW_HASHTABLE_FOREACH_START(ht_keys, value)
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    // Weights
    if(ht_weights != NULL) {
        SW_REDIS_COMMAND_ARGV_FILL("WEIGHTS", 7)

        SW_HASHTABLE_FOREACH_START(ht_weights, value)
            if(Z_TYPE_P(value) != IS_LONG && Z_TYPE_P(value) != IS_DOUBLE &&
               strncasecmp(Z_STRVAL_P(value),"inf",sizeof("inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"-inf",sizeof("-inf")) != 0 &&
               strncasecmp(Z_STRVAL_P(value),"+inf",sizeof("+inf")) != 0)
            {
                zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
                zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Weights must be numeric or '-inf','inf','+inf'");
                for (j = 0; j < i; j++)
                {
                    efree((void* )argv[j]);
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
    size_t key_len, min_len, max_len;
    long offset, count;
    size_t argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if(argc != 3 && argc != 5) {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments");
        RETURN_FALSE;
    }

    if(zend_parse_parameters(argc, "sss|ll", &key,
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
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "min and max arguments must start with '[' or '('");
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
    size_t key_len, min_len, max_len;
    long offset, count;
    int argc = ZEND_NUM_ARGS();

    /* We need either 3 or 5 arguments for this to be valid */
    if(argc != 3 && argc != 5) {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "Must pass either 3 or 5 arguments");
        RETURN_FALSE;
    }

    if(zend_parse_parameters(argc, "sss|ll", &key,
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
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "min and max arguments must start with '[' or '('");
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
    size_t key_len;
    char *start, *end;
    size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt=NULL, *z_ele;
    zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|a", &key, &key_len, &start, &start_len, &end, &end_len,
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
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("withscores")))
            && Z_TYPE_P(z_ele) == IS_TRUE
        )
        {
            withscores = 1;
            argc++;
        }

        // LIMIT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit"))))
        {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit, 0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && Z_TYPE_P(z_off) == IS_LONG && Z_TYPE_P(z_cnt) == IS_LONG)
            {
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
    size_t key_len;
    char *start, *end;
    size_t start_len, end_len;
    long limit_low, limit_high;
    zval *z_opt=NULL, *z_ele;
    zend_bool withscores = 0, has_limit = 0;
    HashTable *ht_opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|a", &key, &key_len, &start, &start_len, &end, &end_len,
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
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("withscores")))
            && Z_TYPE_P(z_ele) == IS_TRUE
        )
        {
            withscores = 1;
            argc++;
        }

        // LIMIT
        if ((z_ele = zend_hash_str_find(ht_opt, ZEND_STRL("limit"))))
        {
            HashTable *ht_limit = Z_ARRVAL_P(z_ele);
            zval *z_off, *z_cnt;
            z_off = zend_hash_index_find(ht_limit,0);
            z_cnt = zend_hash_index_find(ht_limit, 1);
            if (z_off && z_cnt && Z_TYPE_P(z_off) == IS_LONG && Z_TYPE_P(z_cnt) == IS_LONG)
            {
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
    size_t key_len;
    double incrby;
    zval *z_val;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sdz", &key, &key_len, &incrby, &z_val) == FAILURE)
    {
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

    if (argc > 0)
    {
        convert_to_string(&z_args[0]);
    }
    if (argc < 3 || SW_REDIS_COMMAND_ARGS_TYPE(z_args[0]) != IS_STRING)
    {
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
    size_t argc, key_len;
    HashTable *ht_chan;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sa", &key, &key_len,
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
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
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
    sw_redis_command_key_str_str(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ZCOUNT", 6);
}

static PHP_METHOD(swoole_redis_coro, incrBy)
{
    sw_redis_command_key_long(INTERNAL_FUNCTION_PARAM_PASSTHRU, "INCRBY", 6);
}

static PHP_METHOD(swoole_redis_coro, hIncrBy)
{
    char *key, *mem;
    size_t key_len, mem_len;
    long byval;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssl", &key, &key_len,
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
    size_t key_len, mem_len;
    double byval;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssd", &key, &key_len,
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
    size_t key_len, pos_len;
    zval *z_val, *z_pivot;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sszz", &key, &key_len,
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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &db_number) == FAILURE) {
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
    size_t key_len;
    long count = 0;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "sz|l", &key, &key_len,
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
    size_t key_len;
    long start = 0, end = -1;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &key, &key_len,
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
        zend_string *convert_str = zval_get_string(&z_args[j]);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    }
    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV
    efree(z_args);
    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, sMove)
{
    char *src, *dst;
    size_t src_len, dst_len;
    zval *z_val;

    if(zend_parse_parameters(ZEND_NUM_ARGS(), "ssz", &src, &src_len,
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
    if(zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_arr) == FAILURE)
    {
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (redis->defer)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "psubscribe cannot be used with defer enabled");
        RETURN_FALSE;
    }

    sw_coro_check_bind("redis client", redis->cid);

    php_context *context = swoole_get_property(getThis(), 0);
    switch (redis->state)
    {
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE:
        coro_save(context);
        redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
        coro_yield();
        break;
    case SWOOLE_REDIS_CORO_STATE_CONNECT:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is not connected.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_CLOSED:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client connection is closed.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_MULTI:
    case SWOOLE_REDIS_CORO_STATE_PIPELINE:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is multi or pipeline, cann't use subscribe cmd.");
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
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV

    redis->state = SWOOLE_REDIS_CORO_STATE_SUBSCRIBE;

    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, subscribe)
{
    zval *z_arr;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "a", &z_arr) == FAILURE)
    {
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (redis->defer)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "subscribe cannot be used with defer enabled");
        RETURN_FALSE;
    }

    sw_coro_check_bind("redis client", redis->cid);

    php_context *context = swoole_get_property(getThis(), 0);
    switch (redis->state)
    {
    case SWOOLE_REDIS_CORO_STATE_SUBSCRIBE:
        coro_save(context);
        redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
        coro_yield();
        break;
    case SWOOLE_REDIS_CORO_STATE_CONNECT:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client is not connected.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_CLOSED:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis client connection is closed.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_CORO_STATE_MULTI:
    case SWOOLE_REDIS_CORO_STATE_PIPELINE:
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is multi or pipeline, cann't use subscribe cmd.");
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
        zend_string *convert_str = zval_get_string(value);
        SW_REDIS_COMMAND_ARGV_FILL(convert_str->val, convert_str->len)
        zend_string_release(convert_str);
    SW_HASHTABLE_FOREACH_END();

    SW_REDIS_COMMAND(argc)
    SW_REDIS_COMMAND_FREE_ARGV

    redis->state = SWOOLE_REDIS_CORO_STATE_SUBSCRIBE;

    SW_REDIS_COMMAND_YIELD
}

static PHP_METHOD(swoole_redis_coro, multi)
{
    long mode = SW_REDIS_MODE_MULTI;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &mode) == FAILURE)
    {
        RETURN_FALSE;
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed.");
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
    coro_check();
    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_CLOSED);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "connection is not available.");
        RETURN_FALSE;
    }
    if (redis->state != SWOOLE_REDIS_CORO_STATE_MULTI && redis->state != SWOOLE_REDIS_CORO_STATE_PIPELINE)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redis state mode is neither multi nor pipeline!");
        RETURN_FALSE;
    }

    sw_coro_check_bind("redis client", redis->cid);

    if (redis->state == SWOOLE_REDIS_CORO_STATE_MULTI)
    {
        size_t argvlen[1];
        char *argv[1];
        argvlen[0] = 4;
        argv[0] = estrndup("EXEC", 4);
        if (redisAsyncCommandArgv(redis->context, swoole_redis_coro_onResult, NULL, 1, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SW_REDIS_ERR_OTHER);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, getThis(), ZEND_STRL("errMsg"), "redisAsyncCommandArgv() failed.");
            RETURN_FALSE;
        }
        efree(argv[0]);
    }
    redis->iowait = SW_REDIS_CORO_STATUS_WAIT;
    if (redis->defer)
    {
        RETURN_TRUE;
    }
    redis->cid = sw_get_current_cid();
    php_context *context = swoole_get_property(getThis(), 0);
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_redis_coro, request)
{
    SW_REDIS_COMMAND_CHECK

    zval *params = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &params) == FAILURE)
    {
        RETURN_FALSE;
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
    size_t script_len;
    zval *params = NULL;
    long keys_num = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|al", &script, &script_len, &params, &keys_num) == FAILURE)
    {
        RETURN_FALSE;
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
            zend_string *param_str = zval_get_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(param_str->val, param_str->len)
            zend_string_release(param_str);
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
    size_t sha_len;
    zval *params = NULL;
    long keys_num = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|al", &sha, &sha_len, &params, &keys_num) == FAILURE)
    {
        RETURN_FALSE;
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
            zend_string *param_str = zval_get_string(param);
            SW_REDIS_COMMAND_ARGV_FILL(param_str->val, param_str->len)
            zend_string_release(param_str);
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
                zend_string *z_arg_str = zval_get_string(&z_args[j]);
                SW_REDIS_COMMAND_ARGV_FILL(z_arg_str->val, z_arg_str->len)
                zend_string_release(z_arg_str);
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

static void swoole_redis_coro_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply)
{
    zval *val;
    int j;

    zval _val;
    val = &_val;
    bzero(val, sizeof(zval));

    switch (reply->type)
    {
    case REDIS_REPLY_INTEGER:
        ZVAL_LONG(return_value, reply->integer);
        break;

    case REDIS_REPLY_ERROR:
        ZVAL_FALSE(return_value);
        if (redis->context->err == 0)
        {
            if (strncmp(reply->str, "NOAUTH", 6) == 0)
            {
                redis->context->err = SW_REDIS_ERR_NOAUTH;
            }
            else
            {
                redis->context->err = SW_REDIS_ERR_OTHER;
            }
            redis->context->errstr = reply->str;
        }
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr);
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
            zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err);
            zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr);
        }
        break;

    case REDIS_REPLY_STRING:
        if (redis->serialize)
        {
            char *reserve_str = reply->str;
            php_unserialize_data_t s_ht;
            PHP_VAR_UNSERIALIZE_INIT(s_ht);
            if(!php_var_unserialize(return_value,
                (const unsigned char**)&reply->str,
                (const unsigned char*)reply->str + reply->len, &s_ht)) {
                ZVAL_STRINGL(return_value, reply->str, reply->len);
            }
            PHP_VAR_UNSERIALIZE_DESTROY(s_ht);
            reply->str = reserve_str;
        }
        else
        {
            ZVAL_STRINGL(return_value, reply->str, reply->len);
        }
        break;

    case REDIS_REPLY_ARRAY:
        array_init(return_value);
        for (j = 0; j < reply->elements; j++)
        {
            swoole_redis_coro_parse_result(redis, val, reply->element[j]);
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

    swTraceLog(SW_TRACE_REDIS_CLIENT, "resume, fd=%d, object_id=%d", redis->context->c.fd, Z_OBJ_HANDLE_P(redis->object));

    redis->cid = 0;
    redis->iowait = SW_REDIS_CORO_STATUS_READY;

    php_context *sw_current_context = swoole_get_property(redis->object, 0);

    redis_result = result->value;

    int ret = coro_resume(sw_current_context, redis_result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    free_result: if (redis_result)
    {
        zval_ptr_dtor(redis_result);
    }
    efree(result);
}

static void swoole_redis_coro_onResult(redisAsyncContext *c, void *r, void *privdata)
{
    swConnection *_socket = swReactor_get(SwooleG.main_reactor, c->c.fd);
    if (_socket->active == 0)
    {
        return;
    }

    swRedisClient *redis = c->ev.data;
    swRedis_result *result = emalloc(sizeof(swRedis_result));
    redisReply *reply = r;

    zval *type;
    result->value = &result->_value;
    bzero(result->value, sizeof(result->_value));

    swTraceLog(SW_TRACE_REDIS_CLIENT, "get response, fd=%d, object_id=%d", redis->context->c.fd, Z_OBJ_HANDLE_P(redis->object));

    result->redis = redis;
    if (reply == NULL)
    {
        if (redis->state == SWOOLE_REDIS_CORO_STATE_CLOSING)
        {
            error:
            zval_ptr_dtor(result->value);
            efree(result);
            return;
        }
        ZVAL_FALSE(result->value);
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr);
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
        swoole_redis_coro_parse_result(redis, result->value, reply);

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
                efree(result);
                return;
            }
            *result->value = *redis->pipeline_result;
            efree(redis->pipeline_result);
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
            type = zend_hash_index_find(Z_ARRVAL_P(result->value), 0);
            if (!type)
            {
                goto error;
            }
            if (strncasecmp(Z_STRVAL_P(type), "subscribe", 9) == 0 || strncasecmp(Z_STRVAL_P(type), "psubscribe", 10) == 0)
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
    swRedisClient *redis = c->ev.data;
    swRedis_result *result;

    if (redis->timer)
    {
        swTimer_del(&SwooleG.timer, redis->timer);
        redis->timer = NULL;
    }

    if (status != REDIS_OK)
    {
        zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err);
        zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr);
        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0);

        zval *retval = NULL;
        zval *redis_result = NULL;
        SW_MAKE_STD_ZVAL(redis_result);
        ZVAL_BOOL(redis_result, 0);

        php_context *sw_current_context = swoole_get_property(redis->object, 0);

        redis->cid = 0;
        swoole_set_object(redis->object, NULL);
        SwooleG.main_reactor->defer(SwooleG.main_reactor, redis_coro_free, redis);

        int ret = coro_resume(sw_current_context, redis_result, &retval);
        if (ret == CORO_END && retval)
        {
            zval_ptr_dtor(retval);
        }
    }
    else
    {
        result = emalloc(sizeof(swRedis_result));
        result->value = &result->_value;
        bzero(result->value, sizeof(result->_value));
        result->redis = redis;

        ZVAL_BOOL(result->value, 1);
        redis->state = SWOOLE_REDIS_CORO_STATE_READY;
        redis->iowait = SW_REDIS_CORO_STATUS_READY;

        swConnection *_socket = swReactor_get(SwooleG.main_reactor, c->c.fd);
        _socket->active = 1;

        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 1);

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
        swTraceLog(SW_TRACE_REDIS_CLIENT, "fd=%d, object_id=%d", redis->context->c.fd, Z_OBJ_HANDLE_P(redis->object));

        redis->cid = 0;
        redis->context = NULL;
        redis->iowait = SW_REDIS_CORO_STATUS_CLOSED;
        zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0);

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
                zval_ptr_dtor(retval);
            }
            zval_ptr_dtor(redis_result);
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
    swRedisClient *redis = event->socket->object;
    redisAsyncContext *c = redis->context;
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), c->err);
    zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), c->errstr);
    zend_update_property_bool(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("connected"), 0);
    zval *retval = NULL;
    sw_zend_call_method_with_0_params(&redis->object, swoole_redis_coro_class_entry_ptr, NULL, "close", &retval);
    if (retval)
    {
        zval_ptr_dtor(retval);
    }

    return SW_OK;
}

static void swoole_redis_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *result;
    zval *retval = NULL;
    php_context *ctx = tnode->data;

    SW_ALLOC_INIT_ZVAL(result);
    ZVAL_BOOL(result, 0);

    zval _zobject = ctx->coro_params;
    zval *zobject = &_zobject;

    swRedisClient *redis = swoole_get_object(zobject);
    redis->cid = 0;
    redis->timer = NULL;
    zend_update_property_long(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errCode"), ETIMEDOUT);
    zend_update_property_string(swoole_redis_coro_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), strerror(ETIMEDOUT));
    if (redis->context)
    {
        redisAsyncDisconnect(redis->context);
    }

    int ret = coro_resume(ctx, result, &retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
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
