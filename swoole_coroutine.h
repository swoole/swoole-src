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
 +----------------------------------------------------------------------+
 */

#ifndef SWOOLE_COROUTINE_H_
#define SWOOLE_COROUTINE_H_

#define php_context _php_context

typedef struct
{
    zval **current_coro_return_value_ptr_ptr;
    zval *current_coro_return_value_ptr;
    zval **current_eg_return_value_ptr_ptr;
    zend_execute_data *current_execute_data;
    zend_op **current_opline_ptr;
    zend_op *current_opline;
    zend_execute_data *prev_execute_data;
    zend_op_array *current_active_op_array;
    HashTable *current_active_symbol_table;
    zval *current_this;
    zend_class_entry *current_scope;
    zend_class_entry *current_called_scope;
    zend_vm_stack current_vm_stack;
} _php_context;

int coro_create(zend_op_array *op_array, zval **argv, int argc, zval *retval);
void coro_close();
php_context *coro_save(zval *return_value, zval **return_value_ptr, php_context *sw_php_context);
int coro_resume(php_context *sw_current_context, zval *retval);
void coro_yield();
#endif
