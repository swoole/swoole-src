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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */
#ifndef SW_MODULE_H_
#define SW_MODULE_H_

#include "swoole.h"
#include "Server.h"
#include "Client.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _swModule
{
    void *handle;
    char *file;
    char *name;
    swHashMap *functions;
    int (*beforeDispatch)(struct _swModule*, swServer *, swEventData *data);
    int (*beforeReceive)(struct _swModule*, swServer *, swEventData *data);
    int (*shutdown)(struct _swModule*);
} swModule;

typedef swVal* (*swModule_function)(swModule *, int);

swModule* swModule_load(char *so_file);
int swModule_register_function(swModule *module, const char *name, swModule_function func);
int swModule_register_global_function(const char *name, void* func);
void* swModule_get_global_function(char *name, uint32_t length);

static sw_inline void swVal_bool(swVal *val, uint8_t bval)
{
    val->type = SW_VAL_BOOL;
    val->length = 1;
    *(uint8_t *) val->value = bval;
}

static sw_inline void swVal_long(swVal *val, long lval)
{
    val->type = SW_VAL_LONG;
    val->length = sizeof(long);
    memcpy(val->value, &lval, sizeof(long));
}

static sw_inline void swVal_double(swVal *val, double dval)
{
    val->type = SW_VAL_DOUBLE;
    val->length = sizeof(double);
    memcpy(val->value, &dval, sizeof(double));
}

static sw_inline void swVal_string(swVal *val, const char *str, int length)
{
    val->type = SW_VAL_STRING;
    val->length = length;
    memcpy(val->value, str, length);
    val->value[length] = '\0';
}

static sw_inline void swArgs_clear(void)
{
    swString_clear(SwooleG.module_stack);
    SwooleG.module_stack->length = 0;
}

static sw_inline void swArgs_push_null(void)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) (buffer->str + buffer->length);
    val->type = SW_VAL_NULL;
    val->length = 0;
    buffer->length += sizeof(swVal);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swArgs_push_long(long lval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(long))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) (buffer->str + buffer->length);
    val->type = SW_VAL_LONG;
    val->length = sizeof(long);
    memcpy(val->value, &lval, sizeof(long));
    buffer->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swArgs_push_bool(uint8_t bval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(uint8_t))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) (buffer->str + buffer->length);
    val->type = SW_VAL_BOOL;
    val->length = sizeof(uint8_t);
    *((uint8_t *) val->value) = bval;
    buffer->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swArgs_push_double(double fval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(double))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) (buffer->str + buffer->length);
    val->type = SW_VAL_DOUBLE;
    val->length = sizeof(double);
    memcpy(val->value, &fval, sizeof(long));
    buffer->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swArgs_push_string(const char *str, int length)
{
    swString *buffer = SwooleG.module_stack;
    int size = sizeof(swVal) + length + 1;
    if (buffer->size < size)
    {
        swString_extend(buffer, size);
    }
    swVal *val = (swVal *) (buffer->str + buffer->length);
    swVal_string(val, str, length);
    buffer->length += size;
    SwooleG.call_php_func_argc++;
}

static sw_inline long swArgs_pop_long()
{
    swString *buffer = SwooleG.module_stack;
    assert(buffer->length >= buffer->offset);
    long lval;
    swVal *v = (swVal*) (buffer->str + buffer->offset);
    assert(v->type == SW_VAL_LONG);
    memcpy(&lval, v->value, sizeof(long));
    buffer->offset += (sizeof(swVal) + sizeof(long));
    return lval;
}

static sw_inline void swArgs_pop_null(void)
{
    swString *buffer = SwooleG.module_stack;
    assert(buffer->length >= buffer->offset);
    swVal *v = (swVal*) (buffer->str + buffer->offset);
    assert(v->type == SW_VAL_NULL);
    (void)v;
}

static sw_inline uint8_t swArgs_pop_bool()
{
    swString *buffer = SwooleG.module_stack;
    assert(buffer->length >= buffer->offset);
    uint8_t bval;
    swVal *v = (swVal*) (buffer->str + buffer->offset);
    assert(v->type == SW_VAL_LONG);
    bval = *(uint8_t *) v->value;
    buffer->offset += (sizeof(swVal) + sizeof(uint8_t));
    return bval;
}

static sw_inline double swArgs_pop_double()
{
    swString *buffer = SwooleG.module_stack;
    assert(buffer->length >= buffer->offset);
    double dval;
    swVal *v = (swVal*) (buffer->str + buffer->offset);
    assert(v->type == SW_VAL_DOUBLE);
    memcpy(&dval, v->value, sizeof(double));
    buffer->offset += (sizeof(swVal) + sizeof(double));
    return dval;
}

static sw_inline char* swArgs_pop_string(int *length)
{
    swString *buffer = SwooleG.module_stack;
    assert(buffer->length >= buffer->offset);
    swVal *v = (swVal*) (buffer->str + buffer->offset);
    assert(v->type == SW_VAL_STRING);
    buffer->offset += (sizeof(swVal) + v->length + 1);
    *length = v->length;
    return v->value;
}

static sw_inline swVal* swReturnValue_long(long lval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(long))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) buffer->str;
    swVal_long(val, lval);
    return val;
}

static sw_inline swVal* swReturnValue_bool(uint8_t bval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(uint8_t))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) buffer->str;
    swVal_bool(val, bval);
    return val;
}

static sw_inline swVal* swReturnValue_double(double dval)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < sizeof(swVal) + sizeof(double))
    {
        swString_extend(buffer, buffer->size * 2);
    }
    swVal *val = (swVal *) buffer->str;
    swVal_double(val, dval);
    return val;
}

static sw_inline swVal* swReturnValue_string(char *str, int len)
{
    swString *buffer = SwooleG.module_stack;
    if (buffer->size < (sizeof(swVal) + len + 1))
    {
        swString_extend(buffer, sizeof(swVal) + len + 1);
    }
    swVal *val = (swVal *) buffer->str;
    swVal_string(val, str, len);
    return val;
}

static sw_inline long swReturnValue_get_long(long lval)
{
    swString *buffer = SwooleG.module_stack;
    swVal *val = (swVal *) buffer->str;
    assert(val->type == SW_VAL_LONG);
    long *tmp = (long *) val->value;
    return *tmp;
}

static sw_inline uint8_t swReturnValue_get_bool(uint8_t bval)
{
    swString *buffer = SwooleG.module_stack;
    swVal *val = (swVal *) buffer->str;
    assert(val->type == SW_VAL_BOOL);
    return *(uint8_t *) val->value;
}

static sw_inline double swReturnValue_get_double(double dval)
{
    swString *buffer = SwooleG.module_stack;
    swVal *val = (swVal *) buffer->str;
    assert(val->type == SW_VAL_DOUBLE);
    double *tmp = (double *) val->value;
    return *tmp;
}

static sw_inline char* swReturnValue_get_string(int *len)
{
    swString *buffer = SwooleG.module_stack;
    swVal *val = (swVal *) buffer->str;
    assert(val->type == SW_VAL_STRING);
    *len = val->length;
    return val->value;
}

#ifdef __cplusplus
}
#endif

#endif /* SW_MODULE_H_ */
