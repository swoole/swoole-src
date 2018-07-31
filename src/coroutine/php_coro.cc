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
  | Author: shiguangqi <shiguangqi2008@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "coroutine.h"
#include "swoole_coroutine.h"

int php_coro_resume(void *arg)
{
    coro_task *task = (coro_task *)arg;
    COROG.call_stack[COROG.call_stack_size++] = task;
    COROG.current_coro = task;
    swTraceLog(SW_TRACE_COROUTINE,"sw_coro_resume coro id %d", COROG.current_coro->cid);
    task->state = SW_CORO_RUNNING;
    EG(current_execute_data) = task->yield_execute_data;
    EG(vm_stack) = task->yield_stack;
    EG(vm_stack_top) = task->yield_vm_stack_top;
    EG(vm_stack_end) = task->yield_vm_stack_end;

    if (EG(current_execute_data)->prev_execute_data->opline->result_type != IS_UNUSED && task->return_value)
    {
        Z_TRY_ADDREF_P(task->return_value);
        //ZVAL_COPY(SWCC(current_coro_return_value_ptr), retval);
    }
    // main OG
    if (OG(handlers).elements)
    {
        php_output_deactivate(); // free main
        if (!task->current_coro_output_ptr)
        {
            php_output_activate(); // reset output
        }
    }
    // resume output control global
    if (task->current_coro_output_ptr)
    {
        memcpy(SWOG, task->current_coro_output_ptr, sizeof(zend_output_globals));
        efree(task->current_coro_output_ptr);
        task->current_coro_output_ptr = NULL;
    }

    swDebug("cid=%d", task->cid);
    return CORO_END;
}

void php_coro_yield(void *arg)
{
    coro_task *task = (coro_task *)arg;
    zval *return_value = task->return_value;
    COROG.call_stack_size--;
    swTraceLog(SW_TRACE_COROUTINE,"coro_yield coro id %d", task->cid);
    task->state = SW_CORO_YIELD;
    task->is_yield = 1;
    task->return_value = return_value;
    //save vm stack
    task->yield_execute_data = EG(current_execute_data);
    task->yield_stack = EG(vm_stack);
    task->yield_vm_stack_top = EG(vm_stack_top);
    task->yield_vm_stack_end = EG(vm_stack_end);
    //restore vm stack
    EG(vm_stack) = task->origin_stack;
    EG(vm_stack_top) = task->origin_vm_stack_top;
    EG(vm_stack_end) = task->origin_vm_stack_end;

    // save output control global
    if (OG(active))
    {
        zend_output_globals *coro_output_globals_ptr = (zend_output_globals *) emalloc(sizeof(zend_output_globals));
        memcpy(coro_output_globals_ptr, SWOG, sizeof(zend_output_globals));
        task->current_coro_output_ptr = coro_output_globals_ptr;
        php_output_activate(); // reset output
    }
    else
    {
        task->current_coro_output_ptr = NULL;
    }
}
#endif
