/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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
 |         Xinyu    Zhu  <xyzhu1120@gmail.com>                          |
 +----------------------------------------------------------------------+
 */

#ifdef SW_COROUTINE
#ifndef _PHP_SWOOLE_COROUTINE_H_
#define _PHP_SWOOLE_COROUTINE_H_

#include "coroutine.h"
#include <setjmp.h>

#define DEFAULT_MAX_CORO_NUM 3000
#define DEFAULT_STACK_SIZE   8192
#define MAX_CORO_NUM_LIMIT   0x80000

#define CORO_END 0
#define CORO_YIELD 1
#define CORO_LIMIT 2
#define CORO_SAVE 3


#define SW_EX_CV_NUM(ex, n) (((zval ***)(((char *)(ex)) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data)))) + n)
#define SW_EX_CV(var) (*SW_EX_CV_NUM(execute_data, var))

typedef struct _php_context php_context;
typedef struct _coro_task coro_task;

typedef enum
{
	SW_CORO_CONTEXT_RUNNING,
	SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST,
	SW_CORO_CONTEXT_TERM
} php_context_state;

struct _php_context
{
    zval **current_coro_return_value_ptr_ptr;
    zval *current_coro_return_value_ptr;
#if PHP_MAJOR_VERSION < 7
    void *coro_params;
#else
    zval coro_params;
#endif
    void (*onTimeout)(struct _php_context *cxt);
    void *private_data;
    zval **current_eg_return_value_ptr_ptr;
    zend_execute_data *current_execute_data;
#if PHP_MAJOR_VERSION < 7
    zend_op **current_opline_ptr;
    zend_op *current_opline;
    zend_op_array *current_active_op_array;
    HashTable *current_active_symbol_table;
    zval *current_this;
    zend_class_entry *current_scope;
    zend_class_entry *current_called_scope;
#else
    zval *current_vm_stack_top;
    zval *current_vm_stack_end;
    zval *allocated_return_value_ptr;
#endif
    coro_task *current_task;
    zend_vm_stack current_vm_stack;
    php_context_state state;
};

typedef struct _coro_global
{
    uint32_t coro_num;
    uint32_t max_coro_num;
    uint32_t stack_size;
    zend_vm_stack origin_vm_stack;
#if PHP_MAJOR_VERSION >= 7
    zval *origin_vm_stack_top;
    zval *origin_vm_stack_end;
    zval *allocated_return_value_ptr;
#endif
    zend_execute_data *origin_ex;
    coro_task *current_coro;
    zend_bool require;
} coro_global;

struct _coro_task
{
    int cid;
    /**
     * user coroutine
     */
    zval *function;
    time_t start_time;
    void (*post_callback)(void *param);
    void *post_callback_params;
};

typedef struct _swTimer_coro_callback
{
    int ms;
    int cli_fd;
    long *timeout_id;
    void* data;
} swTimer_coro_callback;

extern coro_global COROG;
#define get_current_cid() COROG.current_coro->cid
extern jmp_buf *swReactorCheckPoint;

int sw_coro_resume_parent(php_context *sw_current_context, zval *retval, zval *coro_retval);

int coro_init(TSRMLS_D);
#if PHP_MAJOR_VERSION >= 7
#define coro_create(op_array, argv, argc, retval, post_callback, param) \
        sw_coro_create(op_array, argv, argc, *retval, post_callback, param)
#define coro_save(sw_php_context) \
        sw_coro_save(return_value, sw_php_context);
#define coro_resume(sw_current_context, retval, coro_retval) \
        sw_coro_resume(sw_current_context, retval, *coro_retval)
#define coro_resume_parent(sw_current_context, retval, coro_retval) \
        sw_coro_resume_parent(sw_current_context, retval, coro_retval)

int sw_coro_create(zend_fcall_info_cache *op_array, zval **argv, int argc, zval *retval, void *post_callback, void *param);
php_context *sw_coro_save(zval *return_value, php_context *sw_php_context);
int sw_coro_resume(php_context *sw_current_context, zval *retval, zval *coro_retval);

#else

#define coro_create sw_coro_create
#define coro_save(sw_php_context) sw_coro_save(return_value, return_value_ptr, sw_php_context)
#define coro_resume sw_coro_resume
#define coro_resume_parent(sw_current_context, retval, coro_retval) \

int sw_coro_create(zend_fcall_info_cache *op_array, zval **argv, int argc, zval **retval, void *post_callback, void *param);
php_context *sw_coro_save(zval *return_value, zval **return_value_ptr, php_context *sw_php_context);
int sw_coro_resume(php_context *sw_current_context, zval *retval, zval **coro_retval);
#endif

void coro_check(TSRMLS_D);
void coro_close(TSRMLS_D);
int php_swoole_add_timer_coro(int ms, int cli_fd, long *timeout_id, void* param, swLinkedList_node **node TSRMLS_DC);
int php_swoole_clear_timer_coro(long id TSRMLS_DC);

#endif
#endif
