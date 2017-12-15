#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_sleep, 0, 0, 1)
    ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_coroutine_util, create);
static PHP_METHOD(swoole_coroutine_util, suspend);
static PHP_METHOD(swoole_coroutine_util, cli_wait);
static PHP_METHOD(swoole_coroutine_util, resume);
static PHP_METHOD(swoole_coroutine_util, getuid);
static PHP_METHOD(swoole_coroutine_util, sleep);
static PHP_METHOD(swoole_coroutine_util, call_user_func);
static PHP_METHOD(swoole_coroutine_util, call_user_func_array);

static swHashMap *defer_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    PHP_ME(swoole_coroutine_util, create, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, cli_wait, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, suspend, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, resume, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getuid, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, sleep, arginfo_swoole_coroutine_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func_array, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_coroutine_util_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine", "Swoole\\Coroutine", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce TSRMLS_CC);

    if (SWOOLE_G(use_namespace))
    {
        zend_register_class_alias("swoole_coroutine", swoole_coroutine_util_class_entry_ptr);
    }
    else
    {
        zend_register_class_alias("Swoole\\Coroutine", swoole_coroutine_util_class_entry_ptr);
    }

#if 0
#if PHP_MAJOR_VERSION >= 7
    zend_internal_function *func;
    func = zend_hash_str_find_ptr(CG(function_table), ZEND_STRL("call_user_func"));
    if (func != NULL)
    {
        func->handler = ZEND_MN(swoole_coroutine_util_call_user_func);
    }
    func = zend_hash_str_find_ptr(CG(function_table), ZEND_STRL("call_user_func_array"));
    if (func != NULL)
    {
        func->handler = ZEND_MN(swoole_coroutine_util_call_user_func_array);
    }
#else
    zend_function *func;
    if (zend_hash_find(CG(function_table), ZEND_STRS("call_user_func"), (void **) &func) == SUCCESS)
    {
        func->internal_function.handler = ZEND_MN(swoole_coroutine_util_call_user_func);
    }
    if (zend_hash_find(CG(function_table), ZEND_STRS("call_user_func_array"), (void **) &func) == SUCCESS)
    {
        func->internal_function.handler = ZEND_MN(swoole_coroutine_util_call_user_func_array);
    }
#endif
#endif

    defer_coros = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);
}

static void swoole_coroutine_util_resume(void *data)
{
	php_context *context = (php_context *)data;
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
}

#if PHP_MAJOR_VERSION < 7
#if ZEND_MODULE_API_NO <= 20121212
#define zend_create_execute_data_from_op_array sw_zend_create_execute_data_from_op_array
zend_execute_data *sw_zend_create_execute_data_from_op_array(zend_op_array *op_array, zend_bool nested TSRMLS_DC)
{
	zend_execute_data *execute_data;

	size_t execute_data_size = ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data));
	size_t CVs_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval **) * op_array->last_var * (EG(active_symbol_table) ? 1 : 2));
	size_t Ts_size = ZEND_MM_ALIGNED_SIZE(sizeof(temp_variable)) * op_array->T;
	size_t call_slots_size = ZEND_MM_ALIGNED_SIZE(sizeof(call_slot)) * op_array->nested_calls;
	size_t stack_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * op_array->used_stack;
	size_t total_size = execute_data_size + Ts_size + CVs_size + call_slots_size + stack_size;

        execute_data = zend_vm_stack_alloc(total_size TSRMLS_CC);
        execute_data = (zend_execute_data*)((char*)execute_data + Ts_size);
        execute_data->prev_execute_data = EG(current_execute_data);


        memset(EX_CV_NUM(execute_data, 0), 0, sizeof(zval **) * op_array->last_var);

	execute_data->call_slots = (call_slot*)((char *)execute_data + execute_data_size + CVs_size);


	execute_data->op_array = op_array;

	EG(argument_stack)->top = zend_vm_stack_frame_base(execute_data);

	execute_data->object = NULL;
	execute_data->current_this = NULL;
	execute_data->old_error_reporting = NULL;
	execute_data->symbol_table = EG(active_symbol_table);
	execute_data->call = NULL;
	EG(current_execute_data) = execute_data;
	execute_data->nested = nested;

	if (!op_array->run_time_cache && op_array->last_cache_slot) {
		op_array->run_time_cache = ecalloc(op_array->last_cache_slot, sizeof(void*));
	}

	if (op_array->this_var != -1 && EG(This)) {
 		Z_ADDREF_P(EG(This)); /* For $this pointer */
		if (!EG(active_symbol_table)) {
			SW_EX_CV(op_array->this_var) = (zval **) SW_EX_CV_NUM(execute_data, op_array->last_var + op_array->this_var);
			*SW_EX_CV(op_array->this_var) = EG(This);
		} else {
			if (zend_hash_add(EG(active_symbol_table), "this", sizeof("this"), &EG(This), sizeof(zval *), (void **) EX_CV_NUM(execute_data, op_array->this_var))==FAILURE) {
				Z_DELREF_P(EG(This));
			}
		}
	}

	execute_data->opline = UNEXPECTED((op_array->fn_flags & ZEND_ACC_INTERACTIVE) != 0) && EG(start_op) ? EG(start_op) : op_array->opcodes;
	EG(opline_ptr) = &(execute_data->opline);

	execute_data->function_state.function = (zend_function *) op_array;
	execute_data->function_state.arguments = NULL;

	return execute_data;
}
#endif

static void swoole_corountine_call_function(zend_fcall_info *fci, zend_fcall_info_cache *fci_cache, zval **return_value_ptr, zend_bool use_array, int return_value_used)
{
    SWOOLE_GET_TSRMLS;
    int i;
    zval **origin_return_ptr_ptr;
    zend_op **origin_opline_ptr;
    zend_op_array *origin_active_op_array;
    zend_op_array *op_array = (zend_op_array *)fci_cache->function_handler;
    zend_execute_data *current = EG(current_execute_data);
    void **start, **end, **allocated_params, **old_arguments;

    if (use_array)
    {
        start = (void **)emalloc(sizeof(zval **) * (fci->param_count + 1));
        allocated_params = start;
        end = start + fci->param_count;
        old_arguments = current->function_state.arguments;
        current->function_state.arguments = end;
        for (i = 0; i < fci->param_count; ++i)
        {
            *start = *fci->params[i];
            ++start;
        }
        *start = (void*)(zend_uintptr_t)fci->param_count;
    }
    else
    {
        end = EG(argument_stack)->top - 1;
        start = end - (int)(zend_uintptr_t)(*end);
        zval_ptr_dtor((zval **)(start));
        for (i = 0; i < fci->param_count; ++i)
        {
            *start = *(start + 1);
            ++start;
        }
        *start = (void*)(zend_uintptr_t)fci->param_count;
        EG(argument_stack)->top = start + 1;
        current->function_state.arguments = start;
    }

    origin_return_ptr_ptr = EG(return_value_ptr_ptr);
    if (current->opline->result_type & EXT_TYPE_UNUSED)
    {
        EG(return_value_ptr_ptr) = NULL;
    }
    else
    {
        EG(return_value_ptr_ptr) = return_value_ptr;
    }
    origin_active_op_array = EG(active_op_array);
    origin_opline_ptr = EG(opline_ptr);
    EG(active_op_array) = op_array;
    EG(active_symbol_table) = NULL;
    EG(scope) = fci_cache->calling_scope;
    if (fci_cache->called_scope)
    {
        EG(called_scope) = fci_cache->called_scope;
    }
    else
    {
        EG(called_scope) = NULL;
    }

    if (fci_cache->object_ptr)
    {
        EG(This) = fci_cache->object_ptr;
        if (!PZVAL_IS_REF(EG(This)))
        {
            Z_ADDREF_P(EG(This));
        }
        else
        {
            zval *this_ptr;
            ALLOC_ZVAL(this_ptr);
            *this_ptr = *EG(This);
            INIT_PZVAL(this_ptr);
            zval_copy_ctor(this_ptr);
            EG(This) = this_ptr;
        }
    }
    else
    {
        EG(This) = NULL;
    }

    zend_execute_data *next = zend_create_execute_data_from_op_array(op_array, 0 TSRMLS_CC);
    jmp_buf *prev_checkpoint = swReactorCheckPoint;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));
    if (!setjmp(*swReactorCheckPoint))
    {
        zend_execute_ex(next TSRMLS_CC);
        if (fci->params)
        {
            efree(fci->params);
            if (use_array)
            {
                for (i = 0; i < fci->param_count; ++i)
                {
                    zval *tmp = (zval *) *(--start);
                    zval_ptr_dtor(&tmp);
                }
                efree(allocated_params);
            }
        }
        efree(swReactorCheckPoint);
        swReactorCheckPoint = prev_checkpoint;
        EG(active_op_array) = origin_active_op_array;
        EG(return_value_ptr_ptr) = origin_return_ptr_ptr;
        EG(opline_ptr) = origin_opline_ptr;
    }
    else
    {
        current->original_return_value = origin_return_ptr_ptr;
        next->nested = 1;
        efree(swReactorCheckPoint);
        swReactorCheckPoint = prev_checkpoint;
        if (!return_value_used && return_value_ptr)
            zval_ptr_dtor(return_value_ptr);
        if (fci->params)
        {
            efree(fci->params);
            if (use_array)
            {
                efree(allocated_params);
                current->function_state.arguments = old_arguments;
            }
        }
        longjmp(*swReactorCheckPoint, 1);
    }
}

#else
static void swoole_corountine_call_function(zend_fcall_info *fci, zend_fcall_info_cache *fci_cache, zend_bool use_array)
{
    int i;
    zend_execute_data *call, *current_ex = EG(current_execute_data);
    zend_function *func = fci_cache->function_handler;
    zend_object *object = (func->common.fn_flags & ZEND_ACC_STATIC) ? NULL : fci_cache->object;
#if ZEND_MODULE_API_NO < 20160303
    zend_class_entry* origal_scope = EG(scope);
    call = zend_vm_stack_push_call_frame(ZEND_CALL_TOP_FUNCTION, func,
            fci->param_count, fci_cache->called_scope, object);
    EG(scope) = func->common.scope;
#else
    call = zend_vm_stack_push_call_frame(ZEND_CALL_TOP_FUNCTION | ZEND_CALL_DYNAMIC, func,
            fci->param_count, fci_cache->called_scope, object);
#endif

    for (i = 0; i < fci->param_count; ++i)
    {
        zval *target;
        target = ZEND_CALL_ARG(call, i + 1);
        ZVAL_COPY(target, &fci->params[i]);
    }

    call->symbol_table = NULL;
    zend_init_execute_data(call, &func->op_array, fci->retval);

    jmp_buf *prev_checkpoint = swReactorCheckPoint;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));

    if (!setjmp(*swReactorCheckPoint))
    {
        zend_execute_ex(call);
        efree(swReactorCheckPoint);
        swReactorCheckPoint = prev_checkpoint;
#if ZEND_MODULE_API_NO < 20160303
        EG(scope) = origal_scope;
#endif
    }
    else
    {
        call->prev_execute_data = current_ex->prev_execute_data;
#if ZEND_MODULE_API_NO < 20160303
        ZEND_SET_CALL_INFO(call, ZEND_CALL_NESTED);
#else
        ZEND_SET_CALL_INFO(call, object, ZEND_CALL_DYNAMIC|ZEND_CALL_NESTED);
#endif
        efree(swReactorCheckPoint);
        swReactorCheckPoint = prev_checkpoint;
        if (use_array) {
            zend_fcall_info_args_clear(fci, 1);
        }
        zend_vm_stack_free_args(current_ex);
        longjmp(*swReactorCheckPoint, 1);
    }
}
#endif

#if PHP_MAJOR_VERSION < 7
static PHP_METHOD(swoole_coroutine_util, call_user_func)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "f*",&fci, &fci_cache, &fci.params, &fci.param_count) == FAILURE)
    {
        return;
    }
    swoole_corountine_call_function(&fci, &fci_cache, return_value_ptr, 0, return_value_used);
    RETURN_FALSE;
}

#else
static PHP_METHOD(swoole_coroutine_util, call_user_func)
{
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;

	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_FUNC(fci, fci_cache)
		Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
	ZEND_PARSE_PARAMETERS_END();

    fci.retval = (execute_data->prev_execute_data->opline->result_type != IS_UNUSED) ? return_value : NULL;
    swoole_corountine_call_function(&fci, &fci_cache, 0);
}
#endif

#if PHP_MAJOR_VERSION < 7
static PHP_METHOD(swoole_coroutine_util, call_user_func_array)
{
    zval *params;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fa/",&fci, &fci_cache, &params) == FAILURE)
    {
        return;
    }
    zend_fcall_info_args(&fci, params TSRMLS_CC);
    swoole_corountine_call_function(&fci, &fci_cache, return_value_ptr, 1, return_value_used);
    RETURN_FALSE;
}

#else
static PHP_METHOD(swoole_coroutine_util, call_user_func_array)
{
    zval *params;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_FUNC(fci, fci_cache)
        Z_PARAM_ARRAY_EX(params, 0, 1)
    ZEND_PARSE_PARAMETERS_END();

    zend_fcall_info_args(&fci, params);

    fci.retval = (execute_data->prev_execute_data->opline->result_type != IS_UNUSED) ? return_value : NULL;
    swoole_corountine_call_function(&fci, &fci_cache, 1);

    zend_fcall_info_args_clear(&fci, 1);
}
#endif

static PHP_METHOD(swoole_coroutine_util, suspend)
{
    char *id;
    zend_size_t id_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",&id, &id_len) == FAILURE)
    {
        return;
    }

    swLinkedList *coros_list = swHashMap_find(defer_coros, id, id_len);
    if (coros_list == NULL)
    {
        coros_list = swLinkedList_new(2, NULL);
        if (coros_list == NULL)
        {
            RETURN_FALSE;
        }
        if (swHashMap_add(defer_coros, id, id_len, coros_list) == SW_ERR)
        {
            swLinkedList_free(coros_list);
            RETURN_FALSE;
        }
    }

    php_context *context = emalloc(sizeof(php_context));
    coro_save(context);
    if (swLinkedList_append(coros_list, (void *)context) == SW_ERR) {
        efree(context);
        RETURN_FALSE;
    }
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, create)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
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

    if (swReactorCheckPoint == NULL)
    {
        coro_init(TSRMLS_C);
    }

    zval *retval = NULL;
    zval *args[1];

    jmp_buf *prev_checkpoint = swReactorCheckPoint;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));

    php_context *cxt = emalloc(sizeof(php_context));
    coro_save(cxt);
    int required = COROG.require;
    int ret = coro_create(func_cache, args, 0, &retval, NULL, NULL);
    efree(func_cache);
    efree(swReactorCheckPoint);

    if (ret < 0)
    {
        RETURN_FALSE;
    }

    swReactorCheckPoint = prev_checkpoint;
    coro_resume_parent(cxt, retval, retval);
    COROG.require = required;
    efree(cxt);
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    RETURN_TRUE;
}


static PHP_METHOD(swoole_coroutine_util, cli_wait) {
    if (SwooleGS->start == 1) {
        RETURN_FALSE;
    }
    php_context *cxt = emalloc(sizeof(php_context));
    coro_save(cxt);
    php_swoole_event_wait();
    coro_resume_parent(cxt, NULL, NULL);
    efree(cxt);
    RETURN_LONG(COROG.coro_num);
}

static PHP_METHOD(swoole_coroutine_util, resume)
{
    char *id;
    zend_size_t id_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &id, &id_len) == FAILURE)
    {
        return;
    }

    swLinkedList *coros_list = swHashMap_find(defer_coros, id, id_len);
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

    SwooleG.main_reactor->defer(SwooleG.main_reactor, swoole_coroutine_util_resume, context);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_coroutine_util, getuid)
{
    if (unlikely(COROG.current_coro == NULL))
    {
        RETURN_LONG(-1);
    }
    RETURN_LONG(COROG.current_coro->cid);
}

static void php_coroutine_sleep_timeout(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval *result = NULL;
    SW_MAKE_STD_ZVAL(result);
    ZVAL_BOOL(result, 1);

    php_context *context = (php_context *) tnode->data;
    int ret = coro_resume(context, result, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    efree(context);
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
    if (ms > 8640000)
    {
        swoole_php_fatal_error(E_WARNING, "The given parameters is too big.");
        return;
    }
    if (ms <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Timer must be greater than 0");
        return;
    }

    php_context *context = emalloc(sizeof(php_context));
    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    php_swoole_check_timer(ms);
    if (SwooleG.timer.add(&SwooleG.timer, ms, 0, context, php_coroutine_sleep_timeout) == NULL)
    {
        RETURN_FALSE;
    }

    coro_save(context);
    coro_yield();
}

#endif
