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
#include "async.h"
#include "zend_builtin_functions.h"
#include "ext/standard/file.h"

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
static PHP_METHOD(swoole_coroutine_util, gethostbyname);
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

static swHashMap *defer_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

static zend_class_entry swoole_coroutine_iterator_ce;
static zend_class_entry *swoole_coroutine_iterator_class_entry_ptr;

static zend_class_entry swoole_exit_exception_ce;
static zend_class_entry *swoole_exit_exception_class_entry_ptr;

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exec, ZEND_FN(swoole_coroutine_exec), arginfo_swoole_coroutine_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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
    PHP_ME(swoole_coroutine_util, gethostbyname, arginfo_swoole_coroutine_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getaddrinfo, arginfo_swoole_coroutine_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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
    PHP_ME(swoole_coroutine_iterator, __destruct,  arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
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
    if (sw_get_current_cid() != -1)
    {
        flags |= SW_EXIT_IN_COROUTINE;
    }
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        flags |= SW_EXIT_IN_SERVER;
    }
    if (flags)
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
        }
        else
        {
            exit_status = &_exit_status;
            ZVAL_NULL(exit_status);
        }
        obj = zend_throw_error_exception(swoole_exit_exception_class_entry_ptr, "swoole exit.", 0, E_ERROR TSRMLS_CC);
        ZVAL_OBJ(&ex, obj);
        zend_update_property_long(swoole_exit_exception_class_entry_ptr, &ex, ZEND_STRL("flags"), flags);
        Z_TRY_ADDREF_P(exit_status);
        zend_update_property(swoole_exit_exception_class_entry_ptr, &ex, ZEND_STRL("status"), exit_status);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

void swoole_coroutine_util_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine", "Swoole\\Coroutine", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_coroutine_iterator_ce, "Swoole\\Coroutine\\Iterator", iterator_methods);
    swoole_coroutine_iterator_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_iterator_ce TSRMLS_CC);
    zend_class_implements(swoole_coroutine_iterator_class_entry_ptr TSRMLS_CC, 1, zend_ce_iterator);
#ifdef SW_HAVE_COUNTABLE
    zend_class_implements(swoole_coroutine_iterator_class_entry_ptr TSRMLS_CC, 1, zend_ce_countable);
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
    defer_coros = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);

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
    int cid = sw_get_current_cid();
    if (cid < 0)
    {
        swoole_php_fatal_error(E_ERROR, "can not yield outside coroutine");
        RETURN_FALSE;
    }

    swLinkedList *coros_list = swHashMap_find_int(defer_coros, cid);
    if (coros_list == NULL)
    {
        coros_list = swLinkedList_new(2, NULL);
        if (coros_list == NULL)
        {
            RETURN_FALSE;
        }
        if (swHashMap_add_int(defer_coros, cid, coros_list) == SW_ERR)
        {
            swLinkedList_free(coros_list);
            RETURN_FALSE;
        }
    }

    php_context *context = emalloc(sizeof(php_context));
    coro_save(context);
    if (swLinkedList_append(coros_list, (void *) context) == SW_ERR)
    {
        efree(context);
        RETURN_FALSE;
    }
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, set)
{
    zval *zset = NULL;
    HashTable *vht = NULL;
    zval *v;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
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
    sw_zval_ptr_dtor(&zset);
}

PHP_FUNCTION(swoole_coroutine_create)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }
    if (unlikely(SWOOLE_G(req_status) == PHP_SWOOLE_CALL_USER_SHUTDOWNFUNC_BEGIN))
    {
        zend_function *func = (zend_function *) EG(current_execute_data)->prev_execute_data->func;
        zend_string *destruct = zend_string_init("__destruct", strlen("__destruct"), 0);
        if (zend_string_equals(func->common.function_name, destruct))
        {
            zend_string_release(destruct);
            swoole_php_fatal_error(E_ERROR, "can not use coroutine in __destruct after php_request_shutdown");
            return;
        }
        zend_string_release(destruct);
    }
    char *func_name = NULL;
    zend_fcall_info_cache *func_cache = emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(callback, NULL, 0, &func_name, NULL, func_cache, NULL TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
    if (COROG.active == 0)
    {
        coro_init(TSRMLS_C);
    }
    php_swoole_check_reactor();
    callback = sw_zval_dup(callback);
    sw_zval_add_ref(&callback);

    zval *retval = NULL;
    zval *args[1];
    int cid = coro_create(func_cache, args, 0, &retval, NULL, NULL);
    sw_zval_free(callback);
    efree(func_cache);
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
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
    long id;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id) == FAILURE)
    {
        return;
    }

    swLinkedList *coros_list = swHashMap_find_int(defer_coros, id);
    if (coros_list == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
        RETURN_FALSE;
    }

    php_context *context = swLinkedList_shift(coros_list);
    if (context == NULL)
    {
        swoole_php_fatal_error(E_WARNING, "Nothing can coroResume.");
        RETURN_FALSE;
    }

    zend_vm_stack origin_vm_stack = EG(vm_stack);
    zval *origin_vm_stack_top = EG(vm_stack_top);
    zval *origin_vm_stack_end = EG(vm_stack_end);

    zval *retval = NULL;
    zval *result;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 1);
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(context);
    EG(vm_stack) = origin_vm_stack;
    EG(vm_stack_top) = origin_vm_stack_top;
    EG(vm_stack_end) = origin_vm_stack_end;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, stats)
{
    array_init(return_value);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("stack_size"), COROG.stack_size);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("coroutine_num"), COROG.coro_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("coroutine_peak_num"), COROG.peak_coro_num);
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
    coro_check(TSRMLS_C);

    double seconds;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "d", & seconds) == FAILURE)
    {
        return;
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
    php_swoole_check_timer(ms);

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
        SW_ZVAL_STRINGL(result, event->buf, event->ret, 1);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    php_context *context = (php_context *) event->object;
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(event->buf);
    efree(context);
}

static void aio_onStreamGetLineCompleted(swAio_event *event)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);

    if (event->error == 0)
    {
        SW_ZVAL_STRINGL(result, event->buf, event->ret, 1);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    php_context *context = (php_context *) event->object;
    php_stream *stream;
    php_stream_from_zval_no_verify(stream, &context->coro_params);
    stream->readpos = event->offset;
    stream->writepos = (long) event->req;
    if (event->flags & SW_AIO_EOF)
    {
        stream->eof = 1;
    }

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
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
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(event->buf);
    efree(context);
}

static void aio_onReadFileCompleted(swAio_event *event)
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
        ZVAL_STRINGL(result, event->buf, event->ret);
        sw_free(event->buf);
    }

    php_context *context = (php_context *) event->object;
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(event->req);
    efree(context);
}

static void aio_onWriteFileCompleted(swAio_event *event)
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
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(event->req);
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
    int ret = coro_resume(context, &result, &retval);
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
    int ret = coro_resume(context, &result, &retval);
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
    util_socket *sock = emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    sock->fd = fd;
    sock->buf = zend_string_alloc(length + 1, 0);
    sock->nbytes = length <= 0 ? SW_BUFFER_SIZE_STD : length;

    sock->context.state = SW_CORO_CONTEXT_RUNNING;

    coro_save(&sock->context);
    coro_yield();
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
    util_socket *sock = emalloc(sizeof(util_socket));
    bzero(sock, sizeof(util_socket));
    _socket->object = sock;

    php_context *context = &sock->context;
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->private_data = str;

    sock->nbytes = l_str;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fread)
{
    coro_check(TSRMLS_C);

    zval *handle;
    zend_long length = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|l", &handle, &length) == FAILURE)
    {
        return;
    }
#endif

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async TSRMLS_CC);
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
    if (length <= 0 || file_stat.st_size - _seek < length)
    {
        length = file_stat.st_size - _seek;
    }

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = length + 1;
    ev.buf = emalloc(ev.nbytes);
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_context *context = emalloc(sizeof(php_context));

    ((char *) ev.buf)[length] = 0;
    ev.flags = 0;
    ev.type = SW_AIO_READ;
    ev.object = context;
    ev.handler = swAio_handler_read;
    ev.callback = aio_onReadCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    if (!SwooleAIO.init)
    {
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fgets)
{
    coro_check(TSRMLS_C);

    zval *handle;
    php_stream *stream;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_RESOURCE(handle)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &handle) == FAILURE)
    {
        return;
    }
#endif

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

    if (stream->readbuf == NULL)
    {
        stream->readbuflen = stream->chunk_size;
        stream->readbuf = emalloc(stream->chunk_size);
    }

    ev.nbytes = stream->readbuflen;
    ev.buf = stream->readbuf;
    if (!ev.buf)
    {
        RETURN_FALSE;
    }

    php_context *context = emalloc(sizeof(php_context));

    ev.flags = 0;
    ev.type = SW_AIO_STREAM_GET_LINE;
    ev.object = context;
    ev.callback = aio_onStreamGetLineCompleted;
    ev.handler = swAio_handler_stream_get_line;
    ev.fd = fd;
    ev.offset = stream->readpos;
    ev.req = (void *) (long) stream->writepos;

    if (!SwooleAIO.init)
    {
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("fd=%d, offset=%jd, length=%ld", fd, (intmax_t) ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->coro_params = *handle;
    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fwrite)
{
    coro_check(TSRMLS_C);

    zval *handle;
    char *str;
    zend_size_t l_str;
    zend_long length = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_RESOURCE(handle)
        Z_PARAM_STRING(str, l_str)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|l", &handle, &str, &l_str, &length) == FAILURE)
    {
        return;
    }
#endif

    int async;
    int fd = swoole_convert_to_fd_ex(handle, &async TSRMLS_CC);
    if (fd < 0)
    {
        RETURN_FALSE;
    }

    if (async)
    {
        co_socket_write(fd, str, (length < 0 && length < l_str) ? length : l_str, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    off_t _seek = lseek(fd, 0, SEEK_CUR);
    if (_seek < 0)
    {
        SwooleG.error = errno;
        RETURN_FALSE;
    }
    if (length <= 0 || length > l_str)
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

    php_context *context = emalloc(sizeof(php_context));

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

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, readFile)
{
    coro_check(TSRMLS_C);

    char *filename = NULL;
    size_t l_filename = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(filename, l_filename)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &l_filename) == FAILURE)
    {
        return;
    }
#endif

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    php_context *context = emalloc(sizeof(php_context));

    ev.type = SW_AIO_READ_FILE;
    ev.object = context;
    ev.handler = swAio_handler_read_file;
    ev.callback = aio_onReadFileCompleted;
    ev.req = estrndup(filename, l_filename);

    if (!SwooleAIO.init)
    {
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("readFile(%s)", filename);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, writeFile)
{
    coro_check(TSRMLS_C);

    char *filename = NULL;
    size_t l_filename = 0;
    char *data = NULL;
    size_t l_data = 0;
    zend_long flags = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l", &filename, &l_filename, &data, &l_data, &flags) == FAILURE)
    {
        return;
    }
#endif

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    ev.nbytes = l_data;
    ev.buf = data;

    php_context *context = emalloc(sizeof(php_context));

    ev.type = SW_AIO_WRITE_FILE;
    ev.object = context;
    ev.handler = swAio_handler_write_file;
    ev.callback = aio_onWriteFileCompleted;
    ev.req = estrndup(filename, l_filename);
    ev.flags = O_CREAT | O_WRONLY;

    if (flags & PHP_FILE_APPEND)
    {
        ev.flags |= O_APPEND;
    }
    else
    {
        ev.flags |= O_TRUNC;
    }

    if (!SwooleAIO.init)
    {
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("writeFile(%s, %ld)", filename, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static void coro_dns_onResolveCompleted(swAio_event *event)
{
    php_context *context = event->object;

    zval *retval = NULL;
    zval *result = NULL;

    SW_MAKE_STD_ZVAL(result);

    if (event->error == 0)
    {
        SW_ZVAL_STRING(result, event->buf, 1);
    }
    else
    {
        SwooleG.error = event->error;
        ZVAL_BOOL(result, 0);
    }

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(event->buf);
    efree(context);
}

static void coro_dns_onGetaddrinfoCompleted(swAio_event *event)
{
    php_context *context = event->object;

    zval *retval = NULL;
    zval *result = NULL;

    SW_MAKE_STD_ZVAL(result);

    struct sockaddr_in *addr_v4;
    struct sockaddr_in6 *addr_v6;

    swRequest_getaddrinfo *req = event->req;

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
                addr_v4 = req->result + (i * sizeof(struct sockaddr_in));
                r = inet_ntop(AF_INET, (const void*) &addr_v4->sin_addr, tmp, sizeof(tmp));
            }
            else
            {
                addr_v6 = req->result + (i * sizeof(struct sockaddr_in6));
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

    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(req->hostname);
    efree(req->result);
    if (req->service)
    {
        efree(req->service);
    }
    efree(req);
    efree(context);
}

static PHP_METHOD(swoole_coroutine_util, gethostbyname)
{
    coro_check(TSRMLS_C);

    char *domain_name;
    zend_size_t l_domain_name;
    long family = AF_INET;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &domain_name, &l_domain_name, &family) == FAILURE)
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

    php_context *sw_current_context = emalloc(sizeof(php_context));

    memcpy(ev.buf, domain_name, l_domain_name);
    ((char *) ev.buf)[l_domain_name] = 0;
    ev.flags = family;
    ev.type = SW_AIO_GETHOSTBYNAME;
    ev.object = sw_current_context;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = coro_dns_onResolveCompleted;

    php_swoole_check_aio();

    if (swAio_dispatch(&ev) < 0)
    {
        efree(ev.buf);
        RETURN_FALSE;
    }

    coro_save(sw_current_context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, getaddrinfo)
{
    coro_check(TSRMLS_C);

    char *hostname;
    zend_size_t l_hostname;
    long family = AF_INET;
    long socktype = SOCK_STREAM;
    long protocol = IPPROTO_TCP;
    char *service = NULL;
    zend_size_t l_service = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s|llls", &hostname, &l_hostname, &family, socktype, &protocol,
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

    swRequest_getaddrinfo *req = emalloc(sizeof(swRequest_getaddrinfo));
    bzero(req, sizeof(swRequest_getaddrinfo));

    php_context *sw_current_context = emalloc(sizeof(php_context));

    ev.type = SW_AIO_GETADDRINFO;
    ev.object = sw_current_context;
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

    coro_save(sw_current_context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, getBackTrace)
{
    zend_long cid;
    zend_long options = DEBUG_BACKTRACE_PROVIDE_OBJECT;
    zend_long limit = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|ll", &cid) == FAILURE)
    {
        return;
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
        EG(current_execute_data) = task->yield_execute_data;
        zend_fetch_debug_backtrace(return_value, 0, options, limit);
        EG(current_execute_data) = ex_backup;
    }
}

static PHP_METHOD(swoole_coroutine_iterator, rewind)
{
    coroutine_iterator *itearator = swoole_get_object(getThis());
    bzero(itearator, sizeof(coroutine_iterator));
    itearator->count = COROG.coro_num;
}

static PHP_METHOD(swoole_coroutine_iterator, valid)
{
    coroutine_iterator *itearator = swoole_get_object(getThis());
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
    coroutine_iterator *itearator = swoole_get_object(getThis());
    RETURN_LONG(itearator->current_cid);
}

static PHP_METHOD(swoole_coroutine_iterator, next)
{
    coroutine_iterator *itearator = swoole_get_object(getThis());
    itearator->current_cid++;
}

PHP_METHOD(swoole_coroutine_iterator, key)
{
    coroutine_iterator *itearator = swoole_get_object(getThis());
    RETURN_LONG(itearator->index);
}

static PHP_METHOD(swoole_coroutine_iterator, count)
{
    RETURN_LONG(COROG.coro_num);
}

static PHP_METHOD(swoole_coroutine_iterator, __destruct)
{
    coroutine_iterator *i = swoole_get_object(getThis());
    efree(i);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_coroutine_util, listCoroutines)
{
    object_init_ex(return_value, swoole_coroutine_iterator_class_entry_ptr);
    coroutine_iterator *i = emalloc(sizeof(coroutine_iterator));
    bzero(i, sizeof(coroutine_iterator));
    swoole_set_object(return_value, i);
}
