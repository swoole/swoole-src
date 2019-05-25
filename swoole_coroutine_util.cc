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
#include "php_swoole_cxx.h"

#include "swoole_coroutine.h"
#include "coroutine_c_api.h"
#include "async.h"

#include "zend_builtin_functions.h"
#include "ext/standard/file.h"
#include "ext/spl/spl_array.h"

#include <sys/file.h>
#include <sys/statvfs.h>

#include <string>
#include <unordered_map>

using namespace std;
using swoole::coroutine::System;
using swoole::coroutine::Socket;
using swoole::Coroutine;
using swoole::PHPCoroutine;

typedef struct
{
    php_coro_context context;
    int fd;
    zend_string *buf;
    uint32_t nbytes;
    swTimer_node *timer;
} util_socket;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_set, 0, 0, 1)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_create, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, func, 0)
    ZEND_ARG_VARIADIC_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getContext, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_exec, 0, 0, 1)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, get_error_stream)
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
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_getBackTrace, 0, 0, 0)
    ZEND_ARG_INFO(0, cid)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_coroutine_util, set);
static PHP_METHOD(swoole_coroutine_util, exists);
static PHP_METHOD(swoole_coroutine_util, yield);
static PHP_METHOD(swoole_coroutine_util, resume);
static PHP_METHOD(swoole_coroutine_util, stats);
static PHP_METHOD(swoole_coroutine_util, getCid);
static PHP_METHOD(swoole_coroutine_util, getPcid);
static PHP_METHOD(swoole_coroutine_util, getContext);
static PHP_METHOD(swoole_coroutine_util, list);
static PHP_METHOD(swoole_coroutine_util, sleep);
static PHP_METHOD(swoole_coroutine_util, fread);
static PHP_METHOD(swoole_coroutine_util, fgets);
static PHP_METHOD(swoole_coroutine_util, fwrite);
static PHP_METHOD(swoole_coroutine_util, statvfs);
static PHP_METHOD(swoole_coroutine_util, getaddrinfo);
static PHP_METHOD(swoole_coroutine_util, readFile);
static PHP_METHOD(swoole_coroutine_util, writeFile);
static PHP_METHOD(swoole_coroutine_util, getBackTrace);

static PHP_METHOD(swoole_exit_exception, getFlags);
static PHP_METHOD(swoole_exit_exception, getStatus);

static zend_class_entry *swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_context_ce;
static zend_class_entry *swoole_exit_exception_ce;
static zend_object_handlers swoole_exit_exception_handlers;

static unordered_map<long, Coroutine *> user_yield_coros;

BEGIN_EXTERN_C()
extern int swoole_coroutine_statvfs(const char *path, struct statvfs *buf);
END_EXTERN_C()

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exec, ZEND_FN(swoole_coroutine_exec), arginfo_swoole_coroutine_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer, ZEND_FN(swoole_coroutine_defer), arginfo_swoole_coroutine_defer, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, set, arginfo_swoole_coroutine_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, exists, arginfo_swoole_coroutine_exists, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_util, suspend, yield, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, resume, arginfo_swoole_coroutine_resume, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, stats, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_util, getuid, getCid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getPcid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getContext, arginfo_swoole_coroutine_getContext, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, sleep, arginfo_swoole_coroutine_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fread, arginfo_swoole_coroutine_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fgets, arginfo_swoole_coroutine_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fwrite, arginfo_swoole_coroutine_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, readFile, arginfo_swoole_coroutine_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, writeFile, arginfo_swoole_coroutine_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getaddrinfo, arginfo_swoole_coroutine_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, statvfs, arginfo_swoole_coroutine_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getBackTrace, arginfo_swoole_coroutine_getBackTrace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_MALIAS(swoole_coroutine_util, listCoroutines, list, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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
    if (Coroutine::get_current())
    {
        flags |= SW_EXIT_IN_COROUTINE;
    }
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        flags |= SW_EXIT_IN_SERVER;
    }
    if (flags == SW_EXIT_IN_COROUTINE && Coroutine::count() == 1)
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
        obj = zend_throw_error_exception(swoole_exit_exception_ce, "swoole exit", 0, E_ERROR);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_ce, &ex, ZEND_STRL("flags"), flags);
        Z_TRY_ADDREF_P(exit_status);
        zend_update_property(swoole_exit_exception_ce, &ex, ZEND_STRL("status"), exit_status);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

void swoole_coroutine_util_init(int module_number)
{
    PHPCoroutine::init();

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_util, "Swoole\\Coroutine", NULL, "Co", swoole_coroutine_util_methods, NULL);
    SW_SET_CLASS_CREATE(swoole_coroutine_util, sw_zend_create_object_deny);

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_iterator, "Swoole\\Coroutine\\Iterator", NULL, "Co\\Iterator", NULL, spl_ce_ArrayIterator);

    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_context, "Swoole\\Coroutine\\Context", NULL, "Co\\Context", NULL, spl_ce_ArrayObject);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_DEFAULT_MAX_CORO_NUM", SW_DEFAULT_MAX_CORO_NUM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_MAX_NUM_LIMIT", SW_CORO_MAX_NUM_LIMIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_INIT", SW_CORO_INIT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_WAITING", SW_CORO_WAITING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_RUNNING", SW_CORO_RUNNING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_CORO_END", SW_CORO_END);

    //prohibit exit in coroutine
    SW_INIT_CLASS_ENTRY_EX(swoole_exit_exception, "Swoole\\ExitException", NULL, NULL, swoole_exit_exception_methods, swoole_exception);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("flags"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(swoole_exit_exception_ce, ZEND_STRL("status"), 0, ZEND_ACC_PRIVATE);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_COROUTINE", SW_EXIT_IN_COROUTINE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_EXIT_IN_SERVER", SW_EXIT_IN_SERVER);

    if (SWOOLE_G(cli))
    {
        ori_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
        zend_set_user_opcode_handler(ZEND_EXIT, coro_exit_handler);
    }
}

void swoole_coroutine_shutdown()
{
    PHPCoroutine::shutdown();
}
static PHP_METHOD(swoole_exit_exception, getFlags)
{
    RETURN_LONG(Z_LVAL_P(sw_zend_read_property(swoole_exit_exception_ce, getThis(), ZEND_STRL("flags"), 0)));
}

static PHP_METHOD(swoole_exit_exception, getStatus)
{
    RETURN_ZVAL(sw_zend_read_property(swoole_exit_exception_ce, getThis(), ZEND_STRL("status"), 0), 1, 0);
}

static PHP_METHOD(swoole_coroutine_util, exists)
{
    zend_long cid;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(Coroutine::get_by_cid(cid) != nullptr);
}

static PHP_METHOD(swoole_coroutine_util, yield)
{
    Coroutine* co = Coroutine::get_current_safe();
    user_yield_coros[co->get_cid()] = co;
    co->yield();
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, set)
{
    zval *zset = NULL;
    HashTable *vht = NULL;
    zval *v;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);
    if (php_swoole_array_get_value(vht, "max_coroutine", v))
    {
        zend_long max_num = zval_get_long(v);
        PHPCoroutine::set_max_num(max_num <= 0 ? SW_DEFAULT_MAX_CORO_NUM : max_num);
    }
    if (php_swoole_array_get_value(vht, "c_stack_size", v) || php_swoole_array_get_value(vht, "stack_size", v))
    {
        Coroutine::set_stack_size(zval_get_long(v));
    }
    if (php_swoole_array_get_value(vht, "socket_connect_timeout", v))
    {
        double t = zval_get_double(v);
        if (t != 0) { Socket::default_connect_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_timeout", v))
    {
        double t = zval_get_double(v);
        if (t != 0) { Socket::default_read_timeout = Socket::default_write_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_read_timeout", v))
    {
        double t = zval_get_double(v);
        if (t != 0) { Socket::default_read_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "socket_write_timeout", v))
    {
        double t = zval_get_double(v);
        if (t != 0) { Socket::default_write_timeout = t; }
    }
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        zend_long level = zval_get_long(v);
        SwooleG.log_level = (uint32_t) (level < 0 ? UINT32_MAX : level);
    }
    if (php_swoole_array_get_value(vht, "trace_flags", v))
    {
        SwooleG.trace_flags = (uint32_t) SW_MAX(0, zval_get_long(v));
    }
    if (php_swoole_array_get_value(vht, "dns_cache_expire", v))
    {
        System::set_dns_cache_expire((time_t) zval_get_long(v));
    }
    if (php_swoole_array_get_value(vht, "dns_cache_capacity", v))
    {
        System::set_dns_cache_capacity((size_t) zval_get_long(v));
    }
    if (php_swoole_array_get_value(vht, "display_errors", v))
    {
        SWOOLE_G(display_errors) = zval_is_true(v);
    }
}

PHP_FUNCTION(swoole_clear_dns_cache)
{
    System::clear_dns_cache();
}

PHP_FUNCTION(swoole_coroutine_create)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;

    ZEND_PARSE_PARAMETERS_START(1, -1)
        Z_PARAM_FUNC(fci, fci_cache)
        Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN))
    {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        if (func->common.function_name && unlikely(memcmp(ZSTR_VAL(func->common.function_name), ZEND_STRS("__destruct")) == 0))
        {
            swoole_php_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            RETURN_FALSE;
        }
    }

    long cid = PHPCoroutine::create(&fci_cache, fci.param_count, fci.params);
    if (likely(cid > 0))
    {
        RETURN_LONG(cid);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_coroutine_util, resume)
{
    long cid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &cid) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto coroutine_iterator = user_yield_coros.find(cid);
    if (coroutine_iterator == user_yield_coros.end())
    {
        swoole_php_fatal_error(E_WARNING, "you can not resume the coroutine which is in IO operation");
        RETURN_FALSE;
    }

    Coroutine* co = coroutine_iterator->second;
    user_yield_coros.erase(cid);
    co->resume();
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, stats)
{
    array_init(return_value);
    if (SwooleG.main_reactor)
    {
        add_assoc_long_ex(return_value, ZEND_STRL("event_num"), SwooleG.main_reactor->event_num);
        add_assoc_long_ex(return_value, ZEND_STRL("signal_listener_num"), SwooleG.main_reactor->signal_listener_num);
    }
    add_assoc_long_ex(return_value, ZEND_STRL("aio_task_num"), SwooleAIO.task_num);
    add_assoc_long_ex(return_value, ZEND_STRL("c_stack_size"), Coroutine::get_stack_size());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_num"), Coroutine::count());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_peak_num"), Coroutine::get_peak_num());
    add_assoc_long_ex(return_value, ZEND_STRL("coroutine_last_cid"), Coroutine::get_last_cid());
}

static PHP_METHOD(swoole_coroutine_util, getCid)
{
    RETURN_LONG(PHPCoroutine::get_cid());
}

static PHP_METHOD(swoole_coroutine_util, getPcid)
{
    RETURN_LONG(PHPCoroutine::get_pcid());
}

static PHP_METHOD(swoole_coroutine_util, getContext)
{
    zend_long cid = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_coro_task *task = (php_coro_task *) (EXPECTED(cid == 0) ? Coroutine::get_current_task() : Coroutine::get_task_by_cid(cid));
    if (UNEXPECTED(!task))
    {
        RETURN_NULL();
    }
    if (UNEXPECTED(!task->context))
    {
        object_init_ex(return_value, swoole_coroutine_context_ce);
        task->context = Z_OBJ_P(return_value);
    }
    GC_ADDREF(task->context);
    RETURN_OBJ(task->context);
}

int php_coroutine_reactor_can_exit(swReactor *reactor)
{
    return Coroutine::count() == 0;
}

static PHP_METHOD(swoole_coroutine_util, sleep)
{
    double seconds;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_DOUBLE(seconds)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(seconds < SW_TIMER_MIN_SEC))
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than or equal to " ZEND_TOSTR(SW_TIMER_MIN_SEC));
        RETURN_FALSE;
    }
    System::sleep(seconds);
    RETURN_TRUE;
}

static void aio_onReadCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->error == 0)
    {
        // TODO: Optimization: reduce memory copy
        ZVAL_STRINGL(&result, (char* )event->buf, event->ret);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(&result);
    efree(event->buf);
    efree(context);
}

static void aio_onFgetsCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->ret != -1)
    {
        ZVAL_STRING(&result, (char* )event->buf);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    php_stream *stream;
    php_stream_from_zval_no_verify(stream, &context->coro_params);

    if (event->flags & SW_AIO_EOF)
    {
        stream->eof = 1;
    }

    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(&result);
    efree(context);
}

static void aio_onWriteCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval result;

    if (event->ret < 0)
    {
        SwooleG.error = event->error;
        ZVAL_FALSE(&result);
    }
    else
    {
        ZVAL_LONG(&result, event->ret);
    }

    php_coro_context *context = (php_coro_context *) event->object;
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(event->buf);
    efree(context);
}

static int co_socket_onReadable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_coro_context *context = &sock->context;

    zval *retval = NULL;
    zval result;

    reactor->del(reactor, sock->fd);

    if (sock->timer)
    {
        swTimer_del(&SwooleG.timer, sock->timer);
        sock->timer = NULL;
    }

    int n = read(sock->fd, ZSTR_VAL(sock->buf), sock->nbytes);
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
        ZSTR_VAL(sock->buf)[n] = 0;
        ZSTR_LEN(sock->buf) = n;
        ZVAL_STR(&result, sock->buf);
    }
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    zval_ptr_dtor(&result);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    efree(sock);
    return SW_OK;
}

static int co_socket_onWritable(swReactor *reactor, swEvent *event)
{
    util_socket *sock = (util_socket *) event->socket->object;
    php_coro_context *context = &sock->context;

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
    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
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

    PHPCoroutine::yield_m(return_value, &sock->context);
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

    php_coro_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->private_data = str;

    sock->nbytes = l_str;

    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_coroutine_util, fread)
{
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

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ((char *) ev.buf)[length] = 0;
    ev.flags = 0;
    ev.type = SW_AIO_READ;
    ev.object = context;
    ev.handler = swAio_handler_read;
    ev.callback = aio_onReadCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_coroutine_util, fgets)
{
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
        swoole_php_fatal_error(E_WARNING, "only support file resources");
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

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ev.flags = 0;
    ev.type = SW_AIO_FGETS;
    ev.object = context;
    ev.callback = aio_onFgetsCompleted;
    ev.handler = swAio_handler_fgets;
    ev.fd = fd;
    ev.req = (void *) file;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->coro_params = *handle;
    context->state = SW_CORO_CONTEXT_RUNNING;

    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_coroutine_util, fwrite)
{
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

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ev.flags = 0;
    ev.type = SW_AIO_WRITE;
    ev.object = context;
    ev.handler = swAio_handler_write;
    ev.callback = aio_onWriteCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    php_swoole_check_reactor();
    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_coroutine_util, readFile)
{
    char *filename;
    size_t l_filename;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swString *result = System::read_file(filename, flags & LOCK_EX);
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
    char *filename;
    size_t l_filename;
    char *data;
    size_t l_data;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int _flags = O_CREAT | O_WRONLY;
    if (flags & PHP_FILE_APPEND)
    {
        _flags |= O_APPEND;
    }
    else
    {
        _flags |= O_TRUNC;
    }

    ssize_t retval = System::write_file(filename, data, l_data, flags & LOCK_EX, _flags);
    if (retval < 0)
    {
        RETURN_FALSE
    }
    else
    {
        RETURN_LONG(retval);
    }
}

static void coro_dns_onGetaddrinfoCompleted(swAio_event *event)
{
    php_coro_context *context = (php_coro_context *) event->object;

    zval *retval = NULL;
    zval result;

    struct sockaddr_in *addr_v4;
    struct sockaddr_in6 *addr_v6;

    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) event->req;

    if (req->error == 0)
    {
        array_init(&result);
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
                add_next_index_string(&result, tmp);
            }
        }
    }
    else
    {
        ZVAL_FALSE(&result);
        SwooleG.error = req->error;
    }

    int ret = PHPCoroutine::resume_m(context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(&result);
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
    char *domain_name;
    size_t l_domain_name;
    zend_long family = AF_INET;
    double timeout = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ld", &domain_name, &l_domain_name, &family, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_domain_name == 0)
    {
        swoole_php_fatal_error(E_WARNING, "domain name is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        swoole_php_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    string address = System::gethostbyname(string(domain_name, l_domain_name), family, timeout);
    if (address.empty())
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_STRINGL(address.c_str(), address.length());
    }
}

static PHP_METHOD(swoole_coroutine_util, getaddrinfo)
{
    char *hostname;
    size_t l_hostname;
    zend_long family = AF_INET;
    zend_long socktype = SOCK_STREAM;
    zend_long protocol = IPPROTO_TCP;
    char *service = NULL;
    size_t l_service = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|llls", &hostname, &l_hostname, &family, &socktype, &protocol,
            &service, &l_service) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_hostname == 0)
    {
        swoole_php_fatal_error(E_WARNING, "hostname is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        swoole_php_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    swRequest_getaddrinfo *req = (swRequest_getaddrinfo *) emalloc(sizeof(swRequest_getaddrinfo));
    bzero(req, sizeof(swRequest_getaddrinfo));

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));

    ev.type = SW_AIO_GETADDRINFO;
    ev.object = context;
    ev.handler = swAio_handler_getaddrinfo;
    ev.callback = coro_dns_onGetaddrinfoCompleted;
    ev.req = req;

    req->hostname = estrndup(hostname, l_hostname);
    req->family = family;
    req->socktype = socktype;
    req->protocol = protocol;

    if (l_service > 0)
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

    php_swoole_check_reactor();
    if (swAio_dispatch(&ev) < 0)
    {
        efree(ev.buf);
        RETURN_FALSE;
    }

    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_coroutine_util, getBackTrace)
{
    zend_long cid = 0;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    ZEND_PARSE_PARAMETERS_START(0, 3)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(cid)
        Z_PARAM_LONG(options)
        Z_PARAM_LONG(limit)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!cid || cid == PHPCoroutine::get_cid())
    {
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
    }
    else
    {
        php_coro_task *task = (php_coro_task *) PHPCoroutine::get_task_by_cid(cid);
        if (UNEXPECTED(!task))
        {
            RETURN_FALSE;
        }
        zend_execute_data *ex_backup = EG(current_execute_data);
        EG(current_execute_data) = task->execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

static PHP_METHOD(swoole_coroutine_util, list)
{
    zval zlist;
    array_init(&zlist);
    for (auto &co : Coroutine::coroutines) {
        add_next_index_long(&zlist, co.second->get_cid());
    }
    object_init_ex(return_value, swoole_coroutine_iterator_ce);
    sw_zend_call_method_with_1_params(
        return_value,
        swoole_coroutine_iterator_ce,
        &swoole_coroutine_iterator_ce->constructor,
        (const char *) "__construct",
        NULL,
        &zlist
    );
    zval_ptr_dtor(&zlist);
}

static PHP_METHOD(swoole_coroutine_util, statvfs)
{
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

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(command, command_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(get_error_stream)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_signal_isset_handler(SIGCHLD))
    {
        swoole_php_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_coroutine_exec");
        RETURN_FALSE;
    }

    Coroutine::get_current_safe();
    swoole_coroutine_signal_init();

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
    Socket socket(fd, SW_SOCK_UNIX_STREAM);
    while (1)
    {
        ssize_t retval = socket.read(buffer->str + buffer->length, buffer->size - buffer->length);
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
    socket.close();

    zval zdata;
    if (buffer->length == 0)
    {
        ZVAL_EMPTY_STRING(&zdata);
    }
    else
    {
        ZVAL_STRINGL(&zdata, buffer->str, buffer->length);
    }
    swString_free(buffer);

    int status;
    pid_t _pid = swoole_coroutine_waitpid(pid, &status, 0);
    if (_pid > 0)
    {
        array_init(return_value);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
        add_assoc_zval(return_value, "output", &zdata);
    }
    else
    {
        zval_ptr_dtor(&zdata);
        RETVAL_FALSE;
    }
}

PHP_FUNCTION(swoole_coroutine_defer)
{
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fci_cache = empty_fcall_info_cache;
    php_swoole_fci *defer_fci;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fci_cache)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Coroutine::get_current_safe();
    defer_fci = (php_swoole_fci *) emalloc(sizeof(php_swoole_fci));
    defer_fci->fci = fci;
    defer_fci->fci_cache = fci_cache;
    sw_fci_cache_persist(&defer_fci->fci_cache);
    PHPCoroutine::defer(defer_fci);
}
