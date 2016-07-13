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
extern "C" {
#endif

typedef struct _swModule
{
    char *file;
    char *name;
    swHashMap *functions;
    int (*beforeDispatch)(struct _swModule*, swServer *, swEventData *data);
    int (*beforeReceive)(struct _swModule*, swServer *, swEventData *data);
    int (*shutdown)(struct _swModule*);
} swModule;

typedef swVal* (*swModule_function)(swModule *, swString *, int);

swModule* swModule_load(char *so_file);
int swModule_register_function(swModule *module, const char *name, swModule_function func);

static sw_inline void swArgs_clear(void)
{
    swString_clear(SwooleG.call_php_func_args);
    SwooleG.call_php_func_argc = 0;
}

static sw_inline void swParam_long(long lval)
{
    if (SwooleG.call_php_func_args->size < sizeof(swVal) + sizeof(long))
    {
        swString_extend(SwooleG.call_php_func_args, SwooleG.call_php_func_args->size * 2);
    }
    swVal *val = (swVal *)(SwooleG.call_php_func_args->str + SwooleG.call_php_func_args->length);
    val->type = SW_VAL_LONG;
    val->length = sizeof(long);
    memcpy(val->value, &lval, sizeof(long));
    SwooleG.call_php_func_args->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swParam_bool(uint8_t bval)
{
    if (SwooleG.call_php_func_args->size < sizeof(swVal) + sizeof(uint8_t))
    {
        swString_extend(SwooleG.call_php_func_args, SwooleG.call_php_func_args->size * 2);
    }
    swVal *val = (swVal *)(SwooleG.call_php_func_args->str + SwooleG.call_php_func_args->length);
    val->type = SW_VAL_BOOL;
    val->length = sizeof(uint8_t);
    *((uint8_t *) val->value) = bval;
    SwooleG.call_php_func_args->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swParam_double(double fval)
{
    if (SwooleG.call_php_func_args->size < sizeof(swVal) + sizeof(double))
    {
        swString_extend(SwooleG.call_php_func_args, SwooleG.call_php_func_args->size * 2);
    }
    swVal *val = (swVal *)(SwooleG.call_php_func_args->str + SwooleG.call_php_func_args->length);
    val->type = SW_VAL_DOUBLE;
    val->length = sizeof(double);
    memcpy(val->value, &fval, sizeof(long));
    SwooleG.call_php_func_args->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline void swParam_string(const char *str, int length)
{
    if (SwooleG.call_php_func_args->size < sizeof(swVal) + length)
    {
        swString_extend(SwooleG.call_php_func_args, SwooleG.call_php_func_args->size + (sizeof(swVal) + length));
    }
    swVal *val = (swVal *) (SwooleG.call_php_func_args->str + SwooleG.call_php_func_args->length);
    val->type = SW_VAL_STRING;
    val->length = length;
    memcpy(val->value, str, length);
    SwooleG.call_php_func_args->length += (sizeof(swVal) + val->length);
    SwooleG.call_php_func_argc++;
}

static sw_inline long swParam_parse_long(swString *args)
{
    assert(args->length >= args->offset);
    long lval;
    swVal *v = (swVal*) (args->str + args->offset);
    assert(v->type == SW_VAL_LONG);
    memcpy(&lval, v->value, sizeof(long));
    args->offset += (sizeof(swVal) + sizeof(long));
    return lval;
}

static sw_inline uint8_t swParam_parse_bool(swString *args)
{
    assert(args->length >= args->offset);
    uint8_t bval;
    swVal *v = (swVal*) (args->str + args->offset);
    assert(v->type == SW_VAL_LONG);
    bval = *(uint8_t *) v->value;
    args->offset += (sizeof(swVal) + sizeof(uint8_t));
    return bval;
}

static sw_inline double swParam_parse_double(swString *args)
{
    assert(args->length >= args->offset);
    double dval;
    swVal *v = (swVal*) (args->str + args->offset);
    assert(v->type == SW_VAL_DOUBLE);
    memcpy(&dval, v->value, sizeof(double));
    args->offset += (sizeof(swVal) + sizeof(double));
    return dval;
}

static sw_inline char* swParam_parse_string(swString *args, int *length)
{
    assert(args->length >= args->offset);
    swVal *v = (swVal*) (args->str + args->offset);
    assert(v->type == SW_VAL_STRING);
    args->offset += (sizeof(swVal) + v->length);
    *length = v->length;
    return v->value;
}

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

static sw_inline void swVal_string(swVal *val, char *str, int length)
{
    val->type = SW_VAL_STRING;
    val->length = length;
    memcpy(val->value, str, length);
    val->value[length] = '\0';
}

static sw_inline swVal* swReturnValue_long(long lval)
{
    if (SwooleG.module_return_value->size < sizeof(swVal) + sizeof(long))
    {
        swString_extend(SwooleG.module_return_value, SwooleG.module_return_value->size * 2);
    }
    swVal *val = (swVal *) SwooleG.module_return_value->str;
    swVal_long(val, lval);
    return val;
}

static sw_inline swVal* swReturnValue_bool(uint8_t bval)
{
    if (SwooleG.module_return_value->size < sizeof(swVal) + sizeof(uint8_t))
    {
        swString_extend(SwooleG.module_return_value, SwooleG.module_return_value->size * 2);
    }
    swVal *val = (swVal *) SwooleG.module_return_value->str;
    swVal_bool(val, bval);
    return val;
}

static sw_inline swVal* swReturnValue_double(double dval)
{
    if (SwooleG.module_return_value->size < sizeof(swVal) + sizeof(double))
    {
        swString_extend(SwooleG.module_return_value, SwooleG.module_return_value->size * 2);
    }
    swVal *val = (swVal *) SwooleG.module_return_value->str;
    swVal_double(val, dval);
    return val;
}

static sw_inline swVal* swReturnValue_string(char *str, int len)
{
    if (SwooleG.module_return_value->size < (sizeof(swVal) + len + 1))
    {
        swString_extend(SwooleG.module_return_value, SwooleG.module_return_value->size * 2);
    }
    swVal *val = (swVal *) SwooleG.module_return_value->str;
    swVal_string(val, str, len);
    return val;
}

#ifdef __cplusplus
}
#endif

#endif /* SW_MODULE_H_ */
