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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#include "zend_API.h"
#include "swoole_coroutine.h"
#include <setjmp.h>

#define SWCC(x) sw_current_context->x
#define SW_EX_CV_NUM(ex, n) (((zval ***)(((char *)(ex)) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data)))) + n)
#define SW_EX_CV(var) (*SW_EX_CV_NUM(execute_data, var))

jmp_buf swReactorCheckPoint;

static int coro_num;

int coro_create(zend_fcall_info_cache *fci_cache, zval **argv, int argc, zval *retval)
{
    TSRMLS_FETCH();
    zend_op_array *op_array = (zend_op_array *)fci_cache->function_handler;
    zend_execute_data *execute_data;
    EG(active_symbol_table) = NULL;
    size_t execute_data_size = ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data));
    size_t CVs_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval **) * op_array->last_var * (EG(active_symbol_table) ? 1 : 2));
    size_t Ts_size = ZEND_MM_ALIGNED_SIZE(sizeof(temp_variable)) * op_array->T;
    size_t call_slots_size = ZEND_MM_ALIGNED_SIZE(sizeof(call_slot)) * op_array->nested_calls;
    size_t stack_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * op_array->used_stack;
    size_t total_size = execute_data_size + Ts_size + CVs_size + call_slots_size + stack_size;

    //from generator
    size_t args_size = ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * (argc + 1);

    total_size += execute_data_size + args_size;

    EG(argument_stack) = zend_vm_stack_new_page((total_size + (sizeof(void*) - 1)) / sizeof(void*));
    EG(argument_stack)->prev = NULL;
    execute_data = (zend_execute_data*)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + args_size + Ts_size + execute_data_size);

    /* copy prev_execute_data */
    execute_data->prev_execute_data = (zend_execute_data*)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + args_size);
    memset(execute_data->prev_execute_data, 0, sizeof(zend_execute_data));
    execute_data->prev_execute_data->function_state.function = (zend_function*)op_array;
    execute_data->prev_execute_data->function_state.arguments = (void**)((char*)ZEND_VM_STACK_ELEMETS(EG(argument_stack)) + ZEND_MM_ALIGNED_SIZE(sizeof(zval*)) * argc);

    /* copy arguments */
    *execute_data->prev_execute_data->function_state.arguments = (void*)(zend_uintptr_t)argc;
    if (argc > 0) {
      zval **arg_dst = (zval**)zend_vm_stack_get_arg_ex(execute_data->prev_execute_data, 1);
      int i;
      for (i = 0; i < argc; i++) {
        arg_dst[i] = argv[i];
        Z_ADDREF_P(arg_dst[i]);
      }
    }
    memset(EX_CV_NUM(execute_data, 0), 0, sizeof(zval **) * op_array->last_var);
    execute_data->call_slots = (call_slot*)((char *)execute_data + execute_data_size + CVs_size);
    execute_data->op_array = op_array;

    EG(argument_stack)->top = zend_vm_stack_frame_base(execute_data);

    execute_data->object = NULL;
    execute_data->current_this = NULL;
    execute_data->old_error_reporting = NULL;
    execute_data->symbol_table = NULL;
    execute_data->call = NULL;
    execute_data->nested = 0;

    if (!op_array->run_time_cache && op_array->last_cache_slot) {
      op_array->run_time_cache = ecalloc(op_array->last_cache_slot, sizeof(void*));
    }

    /**
     * comment this temporarily. Consequently, we cannot create a coroutine to run a method of object
     */
    if (fci_cache->object_ptr)
    {
        EG(This) = fci_cache->object_ptr;
        if (!PZVAL_IS_REF(EG(This)))
        {
            Z_ADDREF_P(EG(This));
        } else {
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

    if (op_array->this_var != -1 && EG(This)) {
    //  printf("this pointer");
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

    execute_data->opline = op_array->opcodes;
    EG(opline_ptr) = &((*execute_data).opline);

    execute_data->function_state.function = (zend_function *) op_array;
    execute_data->function_state.arguments = NULL;

    EG(active_op_array) = op_array;
    /*
     * push dummy arguments to protect the stack (maybe push 0??)
     */
    //zend_vm_stack_push((void *)0);

    EG(current_execute_data) = execute_data;
    EG(return_value_ptr_ptr) = &retval;
    EG(This) = 0;
    EG(scope) = fci_cache->calling_scope;
    EG(called_scope) = fci_cache->called_scope;
    ++coro_num;

    if (!setjmp(swReactorCheckPoint)) {
        zend_execute_ex(execute_data TSRMLS_CC);
        coro_close();
        swTrace("create the %d coro with stack %zu\n", coro_num, total_size);
        return 0;
    }
    return 1;
}

sw_inline void coro_close()
{
    void **arguments = EG(current_execute_data)->function_state.arguments;
    if (arguments)
    {
        int arg_count = (int)(zend_uintptr_t)(*arguments);
        zval **arg_start = (zval **)(arguments - arg_count);
        int i;
        for (i = 0; i < arg_count; ++i)
        {
            zval_ptr_dtor(arg_start + i);
        }
    }

    efree(EG(argument_stack));
    --coro_num;
    swTrace("closing coro and %d remained", coro_num);
}

sw_inline php_context *coro_save(zval *return_value, zval **return_value_ptr, php_context *sw_current_context)
{
    TSRMLS_FETCH();
    SWCC(current_coro_return_value_ptr_ptr) = return_value_ptr;
    SWCC(current_coro_return_value_ptr) = return_value;
    SWCC(current_eg_return_value_ptr_ptr) = EG(return_value_ptr_ptr);
    SWCC(current_execute_data) = EG(current_execute_data);
    SWCC(current_opline_ptr) = EG(opline_ptr);
    SWCC(current_opline) = *(EG(opline_ptr));
    SWCC(current_active_op_array) = EG(active_op_array);
    SWCC(current_active_symbol_table) = EG(active_symbol_table);
    SWCC(current_this) = EG(This);
    SWCC(current_scope) = EG(scope);
    SWCC(current_called_scope) = EG(called_scope);
    SWCC(current_vm_stack) = EG(argument_stack);
    return sw_current_context;
}

int coro_resume(php_context *sw_current_context, zval *retval)
{
    TSRMLS_FETCH();
    sw_current_context->current_execute_data->opline++;
    if (SWCC(current_this))
    {
        zval_ptr_dtor(&SWCC(current_this));
    }
    EG(return_value_ptr_ptr) = SWCC(current_eg_return_value_ptr_ptr);
    *(sw_current_context->current_coro_return_value_ptr) = *retval;
    zval_copy_ctor(sw_current_context->current_coro_return_value_ptr);
    EG(current_execute_data) = SWCC(current_execute_data);
    EG(opline_ptr) = SWCC(current_opline_ptr);
    EG(active_op_array) = SWCC(current_active_op_array)  ;
    EG(active_symbol_table) = SWCC(current_active_symbol_table);
    //EG(This) = SWCC(current_this);
    //EG(scope) = SWCC(current_scope);
    //EG(called_scope) = SWCC(current_called_scope);
    EG(This) = EG(current_execute_data)->current_this;
    EG(scope) = EG(current_execute_data)->current_scope;
    EG(called_scope) = EG(current_execute_data)->current_called_scope;
    EG(argument_stack) = SWCC(current_vm_stack);

    sw_current_context->current_execute_data->call--;
    zend_vm_stack_clear_multiple(1 TSRMLS_CC);

    if (!setjmp(swReactorCheckPoint)) {
        zend_execute_ex(sw_current_context->current_execute_data TSRMLS_CC);
        coro_close();
        return 0;
    }
    return 1;
}

sw_inline void coro_yield()
{
    longjmp(swReactorCheckPoint, 1);
}
