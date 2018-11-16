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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */
#include "php_swoole.h"

#include "swoole_coroutine.h"
#include "socket.h"
#include "coroutine_c_api.h"
#include "async.h"
#include "zend_builtin_functions.h"
#include "ext/standard/file.h"

#include <sys/file.h>
#include <sys/statvfs.h>

#include <unordered_map>

using namespace swoole;

typedef struct
{
    php_context context;
    int fd;
    zend_string *buf;
    uint32_t nbytes;
    swTimer_node *timer;
} util_socket;

typedef struct
{
    int current_cid;
    int index;
    int count;
} coroutine_iterator;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_set, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_INFO(0, func)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_sleep, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fread, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fgets, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_fwrite, 0, 0, 2)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_gethostbyname, 0, 0, 1)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, family)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getaddrinfo, 0, 0, 1)
    ZEND_ARG_INFO(0, hostname)
    ZEND_ARG_INFO(0, family)
    ZEND_ARG_INFO(0, socktype)
    ZEND_ARG_INFO(0, protocol)
    ZEND_ARG_INFO(0, service)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_readFile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_writeFile, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_statvfs, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getBackTrace, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_coroutine_util, set);
static PHP_METHOD(swoole_coroutine_util, yield);
static PHP_METHOD(swoole_coroutine_util, resume);
static PHP_METHOD(swoole_coroutine_util, stats);
static PHP_METHOD(swoole_coroutine_util, getuid);
static PHP_METHOD(swoole_coroutine_util, listCoroutines);
static PHP_METHOD(swoole_coroutine_util, sleep);
static PHP_METHOD(swoole_coroutine_util, fread);
static PHP_METHOD(swoole_coroutine_util, fgets);
static PHP_METHOD(swoole_coroutine_util, fwrite);
static PHP_METHOD(swoole_coroutine_util, statvfs);
static PHP_METHOD(swoole_coroutine_util, getaddrinfo);
static PHP_METHOD(swoole_coroutine_util, readFile);
static PHP_METHOD(swoole_coroutine_util, writeFile);
static PHP_METHOD(swoole_coroutine_util, getBackTrace);

static PHP_METHOD(swoole_coroutine_iterator, count);
static PHP_METHOD(swoole_coroutine_iterator, rewind);
static PHP_METHOD(swoole_coroutine_iterator, next);
static PHP_METHOD(swoole_coroutine_iterator, current);
static PHP_METHOD(swoole_coroutine_iterator, key);
static PHP_METHOD(swoole_coroutine_iterator, valid);
static PHP_METHOD(swoole_coroutine_iterator, __destruct);

static PHP_METHOD(swoole_exit_exception, getFlags);
static PHP_METHOD(swoole_exit_exception, getStatus);

static std::unordered_map<int, uint8_t> user_yield_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

static zend_class_entry swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_iterator_class_entry_ptr;

static zend_class_entry swoole_exit_exception_ce;
static zend_class_entry *swoole_exit_exception_class_entry_ptr;

extern "C"
{
int swoole_coroutine_statvfs(const char *path, struct statvfs *buf);
}

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exec, ZEND_FN(swoole_coroutine_exec), arginfo_swoole_coroutine_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, set, arginfo_swoole_coroutine_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_util, suspend, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, resume, arginfo_swoole_coroutine_resume, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, stats, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getuid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, sleep, arginfo_swoole_coroutine_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fread, arginfo_swoole_coroutine_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fgets, arginfo_swoole_coroutine_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fwrite, arginfo_swoole_coroutine_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, readFile, arginfo_swoole_coroutine_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, writeFile, arginfo_swoole_coroutine_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getaddrinfo, arginfo_swoole_coroutine_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, statvfs, arginfo_swoole_coroutine_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getBackTrace, arginfo_swoole_coroutine_getBackTrace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, listCoroutines, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry iterator_methods[] =
{
    PHP_ME(swoole_coroutine_iterator, rewind,      arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, next,        arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, current,     arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, key,         arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, valid,       arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, count,       arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_coroutine_iterator, __destruct,  arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_exit_exception_methods[] =
{
    PHP_ME(swoole_exit_exception, getFlags, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_exit_exception, getStatus, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static user_opcode_handler_t ori_exit_handler = NULL;

enum sw_exit_flags
{
    SW_EXIT_IN_COROUTINE = 1 << 1,
    SW_EXIT_IN_SERVER = 1 << 2
};

static int coro_exit_handler(zend_execute_data *execute_data)
{
    zval ex;
    zend_object *obj;
    zend_long flags = 0;
    if (sw_coro_is_in())
    {
        flags |= SW_EXIT_IN_COROUTINE;
    }
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        flags |= SW_EXIT_IN_SERVER;
    }
    if (flags == SW_EXIT_IN_COROUTINE && COROG.coro_num == 1)
    {
        php_swoole_event_exit();
    }
    else if (flags)
    {
        const zend_op *opline = EX(opline);
        zval _exit_status;
        zval *exit_status = NULL;

        if (opline->op1_type != IS_UNUSED)
        {
            if (opline->op1_type == IS_CONST)
            {
                // see: https://github.com/php/php-src/commit/e70618aff6f447a298605d07648f2ce9e5a284f5
#ifdef EX_CONSTANT
                exit_status = EX_CONSTANT(opline->op1);
#else
                exit_status = RT_CONSTANT(opline, opline->op1);
#endif
            }
            else
            {
                exit_status = EX_VAR(opline->op1.var);
            }
            if (Z_ISREF_P(exit_status))
            {
                exit_status = Z_REFVAL_P(exit_status);
            }
            ZVAL_DUP(&_exit_status, exit_status);
            exit_status = &_exit_status;
        }
        else
        {
            exit_status = &_exit_status;
            ZVAL_NULL(exit_status);
        }
        obj = zend_throw_error_exception(swoole_exit_exception_class_entry_ptr, "swoole exit.", 0, E_ERROR);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_class_entry_ptr, &ex, ZEND_STRL("flags"), flags);
        Z_TRY_ADDREF_P(exit_status);
        zend_update_property(swoole_exit_exception_class_entry_ptr, &ex, ZEND_STRL("status"), exit_status);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

void swoole_coroutine_util_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine", "Swoole\\Coroutine", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce);

    INIT_CLASS_ENTRY(swoole_coroutine_iterator_ce, "Swoole\\Coroutine\\Iterator", iterator_methods);
    swoole_coroutine_iterator_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_iterator_ce);
    zend_class_implements(swoole_coroutine_iterator_class_entry_ptr, 1, zend_ce_iterator);
#ifdef SW_HAVE_COUNTABLE
    zend_class_implements(swoole_coroutine_iterator_class_entry_ptr, 1, zend_ce_countable);
#endif

    if (SWOOLE_G(use_namespace))
    {
        sw_zend_register_class_alias("swoole_coroutine", swoole_coroutine_util_class_entry_ptr);
    }
    else
    {
        sw_zend_register_class_alias("Swoole\\Coroutine", swoole_coroutine_util_class_entry_ptr);
    }

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co", swoole_coroutine_util_class_entry_ptr);
    }

    SWOOLE_DEFINE(DEFAULT_MAX_CORO_NUM);
    SWOOLE_DEFINE(MAX_CORO_NUM_LIMIT);

    //prohibit exit in coroutine
    INIT_CLASS_ENTRY(swoole_exit_exception_ce, "Swoole\\ExitException", swoole_exit_exception_methods);
    swoole_exit_exception_class_entry_ptr = zend_register_internal_class_ex(&swoole_exit_exception_ce, zend_exception_get_default());
    SWOOLE_DEFINE(EXIT_IN_COROUTINE);
    SWOOLE_DEFINE(EXIT_IN_SERVER);

    if (SWOOLE_G(cli))
    {
        ori_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
        zend_set_user_opcode_handler(ZEND_EXIT, coro_exit_handler);
    }
}

static PHP_METHOD(swoole_exit_exception, getFlags)
{
    RETURN_LONG(Z_LVAL_P(sw_zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRL("flags"), 1)));
}

static PHP_METHOD(swoole_exit_exception, getStatus)
{
    RETURN_ZVAL(sw_zend_read_property(Z_OBJCE_P(getThis()), getThis(), ZEND_STRL("status"), 1), 0, 0);
}

/*
 * suspend current coroutine
 */
static PHP_METHOD(swoole_coroutine_util, yield)
{
    coroutine_t* co = coroutine_get_current();
    if (unlikely(!co))
    {
        swoole_php_fatal_error(E_ERROR, "can not yield outside coroutine");
        RETURN_FALSE;
    }
    user_yield_coros[coroutine_get_current_cid()] = 1;
    coroutine_yield(co);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, set)
{
    zval *zset = NULL;
    HashTable *vht = NULL;
    zval *v;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zset) == FAILURE)
    {
        RETURN_FALSE;
    }

    php_swoole_array_separate(zset);
    vht = Z_ARRVAL_P(zset);
    if (php_swoole_array_get_value(vht, "max_coroutine", v))
    {
        convert_to_long(v);
        COROG.max_coro_num = (int) Z_LVAL_P(v);
        if (COROG.max_coro_num <= 0)
        {
            COROG.max_coro_num = DEFAULT_MAX_CORO_NUM;
        }
        else if (COROG.max_coro_num >= MAX_CORO_NUM_LIMIT)
        {
            COROG.max_coro_num = MAX_CORO_NUM_LIMIT;
        }
    }
    if (php_swoole_array_get_value(vht, "stack_size", v))
    {
        convert_to_long(v);
        COROG.stack_size = (uint32_t) Z_LVAL_P(v);
        sw_coro_set_stack_size(COROG.stack_size);
    }
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        convert_to_long(v);
        SwooleG.log_level = (int32_t) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "trace_flags", v))
    {
        convert_to_long(v);
        SwooleG.trace_flags = (int32_t) Z_LVAL_P(v);
    }
    zval_ptr_dtor(zset);
}

PHP_FUNCTION(swoole_coroutine_create)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN))
    {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        if (memcmp(ZSTR_VAL(func->common.function_name), ZEND_STRS("__destruct")) == 0)
        {
            swoole_php_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            RETURN_FALSE;
        }
    }
    char *func_name = NULL;
    zend_fcall_info_cache *func_cache = ( zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(callback, NULL, 0, &func_name, NULL, func_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
    php_swoole_check_reactor();
    callback = sw_zval_dup(callback);
    Z_TRY_ADDREF_P(callback);

    zval *retval = NULL;
    int cid = sw_coro_create(func_cache, NULL, 0, retval);
    sw_zval_free(callback);
    efree(func_cache);
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    if (cid < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(cid);
    }
}

static PHP_METHOD(swoole_coroutine_util, resume)
{
    long cid;
    coroutine_t* co;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (user_yield_coros.find(cid) == user_yield_coros.end())
    {
        swoole_php_fatal_error(E_WARNING, "you can not resume the coroutine which is in IO operation.");
        RETURN_FALSE;
    }
    else if (!(co = coroutine_get_by_id(cid)))
    {
        swoole_php_fatal_error(E_WARNING, "no coroutine can resume.");
        RETURN_FALSE;
    }
    user_yield_coros.erase(cid);
    coroutine_resume(co);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, stats)
{
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("stack_size"), COROG.stack_size);
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), COROG.coro_num);
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peak_num"), COROG.peak_coro_num);
}

static PHP_METHOD(swoole_coroutine_util, getuid)
{
    RETURN_LONG(sw_get_current_cid());
}

int php_coroutine_reactor_can_exit(swReactor *reactor)
{
    return COROG.coro_num == 0;
}

static PHP_METHOD(swoole_coroutine_util, sleep)
{
    coro_check();

    double seconds;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", & seconds) == FAILURE)
    {
        RETURN_FALSE;
    }

    int ms = (int) (seconds * 1000);

    if (SwooleG.serv && swIsMaster())
    {
        swoole_php_fatal_error(E_WARNING, "cannot use timer in master process.");
        return;
    }
    if (ms > SW_TIMER_MAX_VALUE)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        return;
    }
    if (ms <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        return;
    }

    php_swoole_check_reactor();

    swoole_coroutine_sleep(seconds);
    RETURN_TRUE;
}

static void aio_onReadCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);

    if (event->error == 0)
    {
        ZVAL_STRINGL(result, (char* )event->buf, event->ret);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    php_context *context = (php_context *) event->object;
    int ret = sw_coro_resume(context, result, retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    efree(event->buf);
    efree(context);
}

static void aio_onFgetsCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);

    if (event->ret != -1)
    {
        ZVAL_STRING(result, (char* )event->buf);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    php_context *context = (php_context *) event->object;
    php_stream *stream;
    php_stream_from_zval_no_verify(stream, &context->coro_params);

    if (event->flags & SW_AIO_EOF)
    {
        stream->eof = 1;
    }

    int ret = sw_coro_resume(context, result, retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    efree(context);
}

static void aio_onWriteCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval *result = NULL;

    SW_MAKE_STD_ZVAL(result);
    if (event->ret < 0)
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }
    else
    {
        ZVAL_LONG(result, event->ret);
    }

    php_context *context = (php_context *) event->object;
    int ret = sw_coro_resume(context, result, retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    efree(event->buf);
    efree(context);
}

static int co_socket_onReadable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    reactor->del(reactor, sock->fd);

    if (sock->timer)
    {
        swTimer_del(&SwooleG.timer, sock->timer);
        sock->timer = NULL;
    }

    int n = read(sock->fd, sock->buf->val, sock->nbytes);
    if (n < 0)
    {
        ZVAL_FALSE(&result);
        zend_string_free(sock->buf);
    }
    else if (n == 0)
    {
        ZVAL_EMPTY_STRING(&result);
        zend_string_free(sock->buf);
    }
    else
    {
        sock->buf->val[n] = 0;
        sock->buf->len = n;
        ZVAL_STR(&result, sock->buf);
    }
    int ret = sw_coro_resume(context, &result, retval);
    zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(sock);
    return SW_OK;
}

static int co_socket_onWritable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    reactor->del(reactor, sock->fd);

    if (sock->timer)
    {
        swTimer_del(&SwooleG.timer, sock->timer);
        sock->timer = NULL;
    }

    int n = write(sock->fd, context->private_data, sock->nbytes);
    if (n < 0)
    {
        SwooleG.error = errno;
        ZVAL_FALSE(&result);
    }
    else
    {
        ZVAL_LONG(&result, n);
    }
    int ret = sw_coro_resume(context, &result, retval);
    zval_ptr_dtor(&result);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(sock);
    return SW_OK;
}

static void co_socket_read(int fd, zend_long length, INTERNAL_FUNCTION_PARAMETERS)
{
    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_SOCKET))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_CO_UTIL | SW_EVENT_READ, co_socket_onReadable);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_CO_UTIL | SW_EVENT_WRITE, co_socket_onWritable);
    }

    if (SwooleG.main_reactor->add(SwooleG.main_reactor, fd, PHP_SWOOLE_FD_CO_UTIL | SW_EVENT_READ) < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, fd);
    util_socket *sock = (util_socket *) emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    sock->fd = fd;
    sock->buf = zend_string_alloc(length + 1, 0);
    sock->nbytes = length <= 0 ? SW_BUFFER_SIZE_STD : length;

    sock->context.state = SW_CORO_CONTEXT_RUNNING;

    sw_coro_save(return_value, &sock->context);
    sw_coro_yield();
}

static void co_socket_write(int fd, char* str, size_t l_str, INTERNAL_FUNCTION_PARAMETERS)
{
    int ret = write(fd, str, l_str);
    if (ret < 0)
    {
        if (errno == EAGAIN)
        {
            goto _yield;
        }
        SwooleG.error = errno;
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }

    _yield: if (SwooleG.main_reactor->add(SwooleG.main_reactor, fd, PHP_SWOOLE_FD_SOCKET | SW_EVENT_WRITE) < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, fd);
    util_socket *sock = (util_socket *) emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    php_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->private_data = str;

    sock->nbytes = l_str;

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fread)
{
    coro_check();

    zval *handle;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async)
    {
        co_socket_read(fd, length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }

    off_t _seek = lseek(fd, 0, SEEK_CUR);
    if (_seek < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }
    if (length <= 0)
    {
        if (_seek >= file_stat.st_size)
        {
            length = SW_BUFFER_SIZE_STD;
        }
        else
        {
            length = file_stat.st_size - _seek;
        }
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = length + 1;
    ev.buf = emalloc(ev.nbytes);
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_context *context = (php_context *) emalloc(sizeof(php_context));

    ((char *) ev.buf)[length] = 0;
    ev.flags = 0;
    ev.type = SW_AIO_READ;
    ev.object = context;
    ev.handler = swAio_handler_read;
    ev.callback = aio_onReadCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    php_swoole_check_aio();

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fgets)
{
    coro_check();

    zval *handle;
    php_stream *stream;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_RESOURCE(handle)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async == 1)
    {
        swoole_php_fatal_error(E_WARNING, "only support file resources.");
        RETURN_FALSE;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    php_stream_from_res(stream, Z_RES_P(handle));

    FILE *file;

    if (stream->stdiocast)
    {
        file = stream->stdiocast;
    }
    else
    {
        if (php_stream_cast(stream, PHP_STREAM_AS_STDIO, (void**)&file, 1) != SUCCESS || file == NULL)
        {
            RETURN_FALSE
        }
    }

    if (stream->readbuf == NULL)
    {
        stream->readbuflen = stream->chunk_size;
        stream->readbuf = (uchar *) emalloc(stream->chunk_size);
    }

    ev.nbytes = stream->readbuflen;
    ev.buf = stream->readbuf;
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_context *context = (php_context *) emalloc(sizeof(php_context));

    ev.flags = 0;
    ev.type = SW_AIO_FGETS;
    ev.object = context;
    ev.callback = aio_onFgetsCompleted;
    ev.handler = swAio_handler_fgets;
    ev.fd = fd;
    ev.req = (void *) file;

    php_swoole_check_aio();

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->coro_params = *handle;
    context->state = SW_CORO_CONTEXT_RUNNING;

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fwrite)
{
    coro_check();

    zval *handle;
    char *str;
    size_t l_str;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_STRING(str, l_str)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async)
    {
        co_socket_write(fd, str, (length <= 0 || (size_t) length > l_str) ? l_str : length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    off_t _seek = lseek(fd, 0, SEEK_CUR);
    if (_seek < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }
    if (length <= 0 || (size_t) length > l_str)
    {
        length = l_str;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = length;
    ev.buf = estrndup(str, length);

    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_context *context = (php_context *) emalloc(sizeof(php_context));

    ev.flags = 0;
    ev.type = SW_AIO_WRITE;
    ev.object = context;
    ev.handler = swAio_handler_write;
    ev.callback = aio_onWriteCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    php_swoole_check_aio();

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, readFile)
{
    coro_check();

    char *filename = NULL;
    size_t l_filename = 0;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_swoole_check_aio();

    swString *result = swoole_coroutine_read_file(filename, flags & LOCK_EX);
    if (result == NULL)
    {
        RETURN_FALSE;
    }
    else
    {
        RETVAL_STRINGL(result->str, result->length);
        swString_free(result);
    }
}

static PHP_METHOD(swoole_coroutine_util, writeFile)
{
    coro_check();

    char *filename = NULL;
    size_t l_filename = 0;
    char *data = NULL;
    size_t l_data = 0;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = l_data;
    ev.buf = data;

    int _flags = O_CREAT | O_WRONLY;
    if (flags & PHP_FILE_APPEND)
    {
        _flags |= O_APPEND;
    }
    else
    {
        _flags |= O_TRUNC;
    }

    ssize_t retval = swoole_coroutine_write_file(filename, data, l_data, flags & LOCK_EX, _flags);
    if (retval < 0)
    {
        RETURN_FALSE
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static void coro_dns_onResolveCompleted(swAio_event *event)
{
    php_context *context = (php_context *) event->object;

    zval *retval = NULL;
    zval *result = NULL;

    SW_MAKE_STD_ZVAL(result);

    if (event->error == 0)
    {
        ZVAL_STRING(result, (char * )event->buf);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    int ret = sw_coro_resume(context, result, retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    efree(event->buf);
    efree(context);
}

static void coro_dns_onGetaddrinfoCompleted(swAio_event *event)
{
    php_context *context = (php_context *) event->object;

    zval *retval = NULL;
    zval *result = NULL;

    SW_MAKE_STD_ZVAL(result);

    struct sockaddr_in *addr_v4;
    struct sockaddr_in6 *addr_v6;

    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) event->req;

    if (req->error == 0)
    {
        array_init(result);
        int i;
        char tmp[INET6_ADDRSTRLEN];
        const char *r ;

        for (i = 0; i < req->count; i++)
        {
            if (req->family == AF_INET)
            {
                addr_v4 = (struct sockaddr_in *) ((char*) req->result + (i * sizeof(struct sockaddr_in)));
                r = inet_ntop(AF_INET, (const void*) &addr_v4->sin_addr, tmp, sizeof(tmp));
            }
            else
            {
                addr_v6 = (struct sockaddr_in6 *) ((char*) req->result + (i * sizeof(struct sockaddr_in6)));
                r = inet_ntop(AF_INET6, (const void*) &addr_v6->sin6_addr, tmp, sizeof(tmp));
            }
            if (r)
            {
                add_next_index_string(result, tmp);
            }
        }
    }
    else
    {
        ZVAL_BOOL(result, 0);
        SwooleG.error = req->error;
    }

    int ret = sw_coro_resume(context, result, retval);
    if (ret == CORO_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(result);
    efree(req->hostname);
    efree(req->result);
    if (req->service)
    {
        efree(req->service);
    }
    efree(req);
    efree(context);
}

PHP_FUNCTION(swoole_coroutine_gethostbyname)
{
    coro_check();

    char *domain_name;
    size_t l_domain_name;
    long family = AF_INET;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &domain_name, &l_domain_name, &family) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_domain_name <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "domain name is empty.");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        swoole_php_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6.");
        RETURN_FALSE;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    if (l_domain_name < SW_IP_MAX_LENGTH)
    {
        ev.nbytes = SW_IP_MAX_LENGTH;
    }
    else
    {
        ev.nbytes = l_domain_name + 1;
    }

    ev.buf = emalloc(ev.nbytes);
    if (!ev.buf)
    {
        swWarn("malloc failed.");
        RETURN_FALSE;
    }

    php_context *context = (php_context *) emalloc(sizeof(php_context));

    memcpy(ev.buf, domain_name, l_domain_name);
    ((char *) ev.buf)[l_domain_name] = 0;
    ev.flags = family;
    ev.type = SW_AIO_GETHOSTBYNAME;
    ev.object = context;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = coro_dns_onResolveCompleted;

    php_swoole_check_aio();

    if (swAio_dispatch(&ev) < 0)
    {
        efree(ev.buf);
        RETURN_FALSE;
    }

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, getaddrinfo)
{
    coro_check();

    char *hostname;
    size_t l_hostname;
    long family = AF_INET;
    long socktype = SOCK_STREAM;
    long protocol = IPPROTO_TCP;
    char *service = NULL;
    size_t l_service = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|llls", &hostname, &l_hostname, &family, socktype, &protocol,
            &hostname, &l_hostname) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_hostname <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "hostname is empty.");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        swoole_php_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6.");
        RETURN_FALSE;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) emalloc(sizeof(swRequest_getaddrinfo));
    bzero(req, sizeof(swRequest_getaddrinfo));

    php_context *context = (php_context *) emalloc(sizeof(php_context));

    ev.type = SW_AIO_GETADDRINFO;
    ev.object = context;
    ev.handler = swAio_handler_getaddrinfo;
    ev.callback = coro_dns_onGetaddrinfoCompleted;
    ev.req = req;

    req->hostname = estrndup(hostname, l_hostname);
    req->family = family;
    req->socktype = socktype;
    req->protocol = protocol;

    if (service)
    {
        req->service = estrndup(service, l_service);
    }

    if (family == AF_INET)
    {
        req->result = ecalloc(SW_DNS_HOST_BUFFER_SIZE, sizeof(struct sockaddr_in));
    }
    else
    {
        req->result = ecalloc(SW_DNS_HOST_BUFFER_SIZE, sizeof(struct sockaddr_in6));
    }

    php_swoole_check_aio();

    if (swAio_dispatch(&ev) < 0)
    {
        efree(ev.buf);
        RETURN_FALSE;
    }

    sw_coro_save(return_value, context);
    sw_coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, getBackTrace)
{
    zend_long cid;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|ll", &cid) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (cid == sw_get_current_cid())
    {
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
    }
    else
    {
        coro_task *task = (coro_task *) coroutine_get_task_by_cid(cid);
        if (task == NULL)
        {
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

static PHP_METHOD(swoole_coroutine_iterator, rewind)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    bzero(itearator, sizeof(coroutine_iterator));
    itearator->count = COROG.coro_num;
}

static PHP_METHOD(swoole_coroutine_iterator, valid)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    int cid = itearator->current_cid;

    for (; itearator->count > 0 && cid < MAX_CORO_NUM_LIMIT + 1; cid++)
    {
        if (coroutine_get_by_id(cid))
        {
            itearator->current_cid = cid;
            itearator->index++;
            itearator->count--;
            RETURN_TRUE;
        }
    }
    RETURN_FALSE;
}

static PHP_METHOD(swoole_coroutine_iterator, current)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    RETURN_LONG(itearator->current_cid);
}

static PHP_METHOD(swoole_coroutine_iterator, next)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    itearator->current_cid++;
}

PHP_METHOD(swoole_coroutine_iterator, key)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    RETURN_LONG(itearator->index);
}

static PHP_METHOD(swoole_coroutine_iterator, count)
{
    RETURN_LONG(COROG.coro_num);
}

static PHP_METHOD(swoole_coroutine_iterator, __destruct)
{
    coroutine_iterator *itearator = (coroutine_iterator *) swoole_get_object(getThis());
    efree(itearator);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_coroutine_util, listCoroutines)
{
    object_init_ex(return_value, swoole_coroutine_iterator_class_entry_ptr);
    coroutine_iterator *itearator = (coroutine_iterator *) emalloc(sizeof(coroutine_iterator));
    bzero(itearator, sizeof(coroutine_iterator));
    swoole_set_object(return_value, itearator);
}

static PHP_METHOD(swoole_coroutine_util, statvfs)
{
    coro_check();

    char *path;
    size_t l_path;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, l_path)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    struct statvfs _stat;
    swoole_coroutine_statvfs(path, &_stat);

    array_init(return_value);
    add_assoc_long(return_value, "bsize", _stat.f_bsize);
    add_assoc_long(return_value, "frsize", _stat.f_frsize);
    add_assoc_long(return_value, "blocks", _stat.f_blocks);
    add_assoc_long(return_value, "bfree", _stat.f_bfree);
    add_assoc_long(return_value, "bavail", _stat.f_bavail);
    add_assoc_long(return_value, "files", _stat.f_files);
    add_assoc_long(return_value, "ffree", _stat.f_ffree);
    add_assoc_long(return_value, "favail", _stat.f_favail);
    add_assoc_long(return_value, "fsid", _stat.f_fsid);
    add_assoc_long(return_value, "flag", _stat.f_flag);
    add_assoc_long(return_value, "namemax", _stat.f_namemax);
}

PHP_FUNCTION(swoole_coroutine_exec)
{
    char *command;
    size_t command_len;
    zend_bool get_error_stream = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|b", &command, &command_len, &get_error_stream) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (php_swoole_signal_isset_handler(SIGCHLD))
    {
        swoole_php_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_coroutine_exec.");
        RETURN_FALSE;
    }

    coro_check();
    swoole_coroutine_signal_init();
    php_swoole_check_reactor();

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, get_error_stream);
    if (fd < 0)
    {
        swoole_php_error(E_WARNING, "Unable to execute '%s'", command);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(1024);
    if (buffer == NULL)
    {
        RETURN_FALSE;
    }

    swSetNonBlock(fd);
    Socket sock(fd, SW_SOCK_UNIX_STREAM);
    while (1)
    {
        ssize_t retval = sock.read(buffer->str + buffer->length, buffer->size - buffer->length);
        if (retval > 0)
        {
            buffer->length += retval;
            if (buffer->length == buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    break;
                }
            }
        }
        else
        {
            break;
        }
    }

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    if (buffer->length == 0)
    {
        ZVAL_EMPTY_STRING(zdata);
    }
    else
    {
        ZVAL_STRINGL(zdata, buffer->str, buffer->length);
    }

    int status;
    pid_t _pid = swoole_coroutine_waitpid(pid, &status, 0);
    if (_pid > 0)
    {
        array_init(return_value);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
        add_assoc_zval(return_value, "output", zdata);
    }
    else
    {
        zval_ptr_dtor(zdata);
        RETVAL_FALSE;
    }

    swString_free(buffer);
}
