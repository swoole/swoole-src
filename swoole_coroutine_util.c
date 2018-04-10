#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "async.h"
#include "swoole_coroutine.h"
#include "ext/standard/file.h"

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_suspend, 0, 0, 1)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_resume, 0, 0, 1)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_call_user_func, 0, 0, 1)
    ZEND_ARG_INFO(0, func)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_coroutine_call_user_func_array, 0, 0, 2)
    ZEND_ARG_INFO(0, func)
    ZEND_ARG_ARRAY_INFO(0, params, 0)
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

static PHP_METHOD(swoole_coroutine_util, set);
static PHP_METHOD(swoole_coroutine_util, suspend);
static PHP_METHOD(swoole_coroutine_util, cli_wait);
static PHP_METHOD(swoole_coroutine_util, resume);
static PHP_METHOD(swoole_coroutine_util, getuid);
static PHP_METHOD(swoole_coroutine_util, sleep);
static PHP_METHOD(swoole_coroutine_util, fread);
static PHP_METHOD(swoole_coroutine_util, fgets);
static PHP_METHOD(swoole_coroutine_util, fwrite);
static PHP_METHOD(swoole_coroutine_util, gethostbyname);
static PHP_METHOD(swoole_coroutine_util, getaddrinfo);
static PHP_METHOD(swoole_coroutine_util, readFile);
static PHP_METHOD(swoole_coroutine_util, writeFile);
static PHP_METHOD(swoole_coroutine_util, call_user_func);
static PHP_METHOD(swoole_coroutine_util, call_user_func_array);

static swHashMap *defer_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

static const zend_function_entry swoole_coroutine_util_methods[] =
{
    ZEND_FENTRY(create, ZEND_FN(swoole_coroutine_create), arginfo_swoole_coroutine_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exec, ZEND_FN(swoole_coroutine_exec), arginfo_swoole_coroutine_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, set, arginfo_swoole_coroutine_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, cli_wait, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, suspend, arginfo_swoole_coroutine_suspend, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, resume, arginfo_swoole_coroutine_resume, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getuid, arginfo_swoole_coroutine_void, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, sleep, arginfo_swoole_coroutine_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fread, arginfo_swoole_coroutine_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fgets, arginfo_swoole_coroutine_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, fwrite, arginfo_swoole_coroutine_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, readFile, arginfo_swoole_coroutine_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, writeFile, arginfo_swoole_coroutine_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, gethostbyname, arginfo_swoole_coroutine_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, getaddrinfo, arginfo_swoole_coroutine_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func, arginfo_swoole_coroutine_call_user_func, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func_array, arginfo_swoole_coroutine_call_user_func_array, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_coroutine_util_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine", "Swoole\\Coroutine", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce TSRMLS_CC);

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

static void coroutine_resume_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    php_context *context = (php_context *)tnode->data;
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
        if (use_array)
        {
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

    if (fci_cache.function_handler->type == ZEND_INTERNAL_FUNCTION || COROG.current_coro == NULL)
    {
        fci.retval = return_value;
        zend_call_function(&fci, &fci_cache);
    }
    else
    {
        fci.retval = (execute_data->prev_execute_data->opline->result_type != IS_UNUSED) ? return_value : NULL;
        swoole_corountine_call_function(&fci, &fci_cache, 0);
    }
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
	// restore scope
#if ZEND_MODULE_API_NO < 20160303
	EG(scope) = execute_data->prev_execute_data->called_scope;
#else
	execute_data->func->common.scope = execute_data->prev_execute_data->func->common.scope; // PHP >= 7.1
#endif

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_FUNC(fci, fci_cache)
        Z_PARAM_ARRAY_EX(params, 0, 1)
    ZEND_PARSE_PARAMETERS_END();

    zend_fcall_info_args(&fci, params);

    if (fci_cache.function_handler->type == ZEND_INTERNAL_FUNCTION || COROG.current_coro == NULL)
    {
        fci.retval = return_value;
        zend_call_function(&fci, &fci_cache);
    }
    else
    {
        fci.retval = (execute_data->prev_execute_data->opline->result_type != IS_UNUSED) ? return_value : NULL;
        swoole_corountine_call_function(&fci, &fci_cache, 1);
    }

    zend_fcall_info_args_clear(&fci, 1);
}
#endif

static PHP_METHOD(swoole_coroutine_util, suspend)
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

    php_swoole_check_reactor();

    callback = sw_zval_dup(callback);
    sw_zval_add_ref(&callback);

    zval *retval = NULL;
    zval *args[1];

    jmp_buf *prev_checkpoint = swReactorCheckPoint;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));

    php_context *ctx = emalloc(sizeof(php_context));
    coro_save(ctx);
    int required = COROG.require;
    int ret = coro_create(func_cache, args, 0, &retval, NULL, NULL);

    if (COROG.current_coro)
    {
        COROG.current_coro->function = callback;
    }
    else
    {
        sw_zval_free(callback);
    }

    efree(func_cache);
    efree(swReactorCheckPoint);

    if (ret < 0)
    {
        RETURN_FALSE;
    }

    swReactorCheckPoint = prev_checkpoint;
    coro_resume_parent(ctx, retval, retval);
    COROG.require = required;
    efree(ctx);
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

static PHP_METHOD(swoole_coroutine_util, cli_wait)
{
    if (SwooleGS->start == 1)
    {
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

    if (SwooleG.main_reactor->start == 0)
    {
        php_swoole_check_timer(1);
        SwooleG.timer.add(&SwooleG.timer, 1, 0, context, coroutine_resume_onTimeout);
    }
    else
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, swoole_coroutine_util_resume, context);
    }

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

int php_coroutine_reactor_can_exit(swReactor *reactor)
{
    return COROG.coro_num != 0;
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

    php_context *context = emalloc(sizeof(php_context));
    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    php_swoole_check_reactor();
    php_swoole_check_timer(ms);
    if (SwooleG.timer.add(&SwooleG.timer, ms, 0, context, php_coroutine_sleep_timeout) == NULL)
    {
        RETURN_FALSE;
    }

    coro_save(context);
    coro_yield();
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

static PHP_METHOD(swoole_coroutine_util, fread)
{
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

    int fd = swoole_convert_to_fd(handle TSRMLS_CC);

    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        RETURN_FALSE;
    }

    off_t _seek = lseek(fd, 0, SEEK_CUR);
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
    ev.callback = aio_onReadCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    if (!SwooleAIO.init)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("fd=%d, offset=%ld, length=%ld", fd, ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fgets)
{
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

    int fd = swoole_convert_to_fd(handle TSRMLS_CC);
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
    ev.fd = fd;
    ev.offset = stream->readpos;
    ev.req = (void *) (long) stream->writepos;

    if (!SwooleAIO.init)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        php_swoole_check_reactor();
        swAio_init();
    }

    swTrace("fd=%d, offset=%ld, length=%ld", fd, ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->coro_params = *handle;
    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, fwrite)
{
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

    int fd = swoole_convert_to_fd(handle TSRMLS_CC);

    off_t _seek = lseek(fd, 0, SEEK_CUR);
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
    ev.callback = aio_onWriteCompleted;
    ev.fd = fd;
    ev.offset = _seek;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        SwooleAIO.init = 0;
    }
    php_swoole_check_aio();

    swTrace("fd=%d, offset=%ld, length=%ld", fd, ev.offset, ev.nbytes);

    int ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        efree(context);
        RETURN_FALSE;
    }

    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, readFile)
{
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
    ev.callback = aio_onReadFileCompleted;
    ev.req = estrndup(filename, l_filename);

    if (!SwooleAIO.init)
    {
        SwooleAIO.mode = SW_AIO_BASE;
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

    context->onTimeout = NULL;
    context->state = SW_CORO_CONTEXT_RUNNING;

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_coroutine_util, writeFile)
{
    char *filename = NULL;
    size_t l_filename = 0;
    char *data = NULL;
    size_t l_data = 0;
    long flags = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &filename, &l_filename, &data, &l_data) == FAILURE)
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
        SwooleAIO.mode = SW_AIO_BASE;
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

    context->onTimeout = NULL;
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
    ev.callback = coro_dns_onResolveCompleted;

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        SwooleAIO.init = 0;
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

static PHP_METHOD(swoole_coroutine_util, getaddrinfo)
{
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

    if (SwooleAIO.mode == SW_AIO_LINUX)
    {
        SwooleAIO.mode = SW_AIO_BASE;
        SwooleAIO.init = 0;
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

#endif
