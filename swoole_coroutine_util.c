#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"

static PHP_METHOD(swoole_coroutine_util, suspend);
static PHP_METHOD(swoole_coroutine_util, resume);
static PHP_METHOD(swoole_coroutine_util, call_user_func);
static PHP_METHOD(swoole_coroutine_util, call_user_func_array);

static swHashMap *defer_coros;

static zend_class_entry swoole_coroutine_util_ce;
static zend_class_entry *swoole_coroutine_util_class_entry_ptr;

extern jmp_buf *swReactorCheckPoint;
static const zend_function_entry swoole_coroutine_util_methods[] =
{
    PHP_ME(swoole_coroutine_util, suspend, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, resume, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_util, call_user_func_array, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_coroutine_util_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_coroutine_util_ce, "swoole_coroutine", "Swoole\\Coroutine", swoole_coroutine_util_methods);
    swoole_coroutine_util_class_entry_ptr = zend_register_internal_class(&swoole_coroutine_util_ce TSRMLS_CC);

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
static void swoole_corountine_call_function(zend_fcall_info *fci, zend_fcall_info_cache *fci_cache, zval **return_value_ptr, zend_bool use_array)
{
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

    zend_execute_data *next = zend_create_execute_data_from_op_array(op_array, 0);
    jmp_buf *prev_checkpoint = swReactorCheckPoint;
    swReactorCheckPoint = emalloc(sizeof(jmp_buf));
    if (!setjmp(*swReactorCheckPoint))
    {
        //++swReactorCheckPoint.cnt;
        zend_execute_ex(next);
        if (fci->params)
        {
            efree(fci->params);
            if (use_array)
            {
                efree(allocated_params);
            }
        }
        //--swReactorCheckPoint.cnt;
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
        //--swReactorCheckPoint.cnt;
        efree(swReactorCheckPoint);
        swReactorCheckPoint = prev_checkpoint;
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
}
#endif


static PHP_METHOD(swoole_coroutine_util, call_user_func)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

#if PHP_MAJOR_VERSION < 7
    zval_ptr_dtor(return_value_ptr);
#endif
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "f*",&fci, &fci_cache, &fci.params, &fci.param_count) == FAILURE)
    {
        return;
    }

#if PHP_MAJOR_VERSION < 7
    swoole_corountine_call_function(&fci, &fci_cache, return_value_ptr, 0);
#else
    swoole_corountine_call_function(&fci, &fci_cache, 0);
#endif
}

static PHP_METHOD(swoole_coroutine_util, call_user_func_array)
{
    zval *params;
    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

#if PHP_MAJOR_VERSION < 7
    zval_ptr_dtor(return_value_ptr);
#endif

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "fa/",&fci, &fci_cache, &params) == FAILURE)
    {
        return;
    }
    zend_fcall_info_args(&fci, params);
#if PHP_MAJOR_VERSION < 7
    swoole_corountine_call_function(&fci, &fci_cache, return_value_ptr, 1);
#else
    swoole_corountine_call_function(&fci, &fci_cache, 1);
#endif
}

static PHP_METHOD(swoole_coroutine_util, suspend)
{
	char *id;
	int id_len;

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

static PHP_METHOD(swoole_coroutine_util, resume)
{
	char *id;
	int id_len;

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
#endif
