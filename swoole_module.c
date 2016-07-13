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

#include "php_swoole.h"
#include "module.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_module_call, 0, 0, 2)
    ZEND_ARG_INFO(0, func)
    ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

static zend_class_entry swoole_module_ce;
static zend_class_entry *swoole_module_class_entry_ptr;

static swVal* swoole_call_php_func(const char *name, int length);
static PHP_METHOD(swoole_module, __call);

static const zend_function_entry swoole_module_methods[] =
{
    PHP_ME(swoole_module, __call, arginfo_swoole_module_call, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int swVal_to_zval(swVal *val, zval *zv)
{
    uint8_t _bool_val = 0;
    long _int_val = 0;
    double _float_val = 0.0;

    if (val == NULL)
    {
        return SW_ERR;
    }
    switch(val->type)
    {
    case SW_VAL_BOOL:
        memcpy(&_bool_val, val->value, sizeof(_bool_val));
        ZVAL_BOOL(zv, _bool_val);
        break;
    case SW_VAL_DOUBLE:
        memcpy(&_float_val, val->value, sizeof(_float_val));
        ZVAL_DOUBLE(zv, _float_val);
        break;
    case SW_VAL_LONG:
        memcpy(&_int_val, val->value, sizeof(_int_val));
        ZVAL_LONG(zv, _int_val);
        break;
    case SW_VAL_STRING:
        SW_ZVAL_STRINGL(zv, val->value, val->length, 1);
        break;
    default:
        swWarn("unknown type.");
        return SW_ERR;
    }
    return SW_OK;
}

void swoole_module_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_module_ce, "swoole_module", "Swoole\\Module", swoole_module_methods);
    swoole_module_class_entry_ptr = zend_register_internal_class(&swoole_module_ce TSRMLS_CC);

    SwooleG.call_php_func = swoole_call_php_func;
    SwooleG.call_php_func_args = swString_new(8192);
    if (SwooleG.call_php_func_args == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "swString_new(8192) failed.");
    }
    SwooleG.module_return_value = swString_new(8192);
    if (SwooleG.module_return_value == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "swString_new(8192) failed.");
    }
}

PHP_FUNCTION(swoole_load_module)
{
    char *name;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &len) == FAILURE)
    {
        return;
    }
    if (access(name, R_OK) < 0)
    {
        swoole_php_error(E_WARNING, "file[%s] not found.", name);
        RETURN_FALSE;
    }
    swModule *module = swModule_load(name);
    if (module == NULL)
    {
        RETURN_FALSE;
    }
    object_init_ex(return_value, swoole_module_class_entry_ptr);
    swoole_set_object(return_value, module);
}

static PHP_METHOD(swoole_module, __call)
{
    zval *params;
    char *name;
    zend_size_t name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &name_len, &params) == FAILURE)
    {
        return;
    }
    swModule *module = swoole_get_object(getThis());
    if (module == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Please use swoole_load_module().");
        return;
    }
    swModule_function func = swHashMap_find(module->functions, name, name_len);
    if (func == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Module[%s] does not have [%s] function.", module->name, name);
        return;
    }

    zval *value;
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
        switch(SW_Z_TYPE_P(value))
        {
        case IS_STRING:
            swParam_string(Z_STRVAL_P(value), Z_STRLEN_P(value));
            break;
        case IS_LONG:
            swParam_long(Z_LVAL_P(value));
            break;
        case IS_DOUBLE:
            swParam_double(Z_DVAL_P(value));
            break;
#if PHP_MAJOR_VERSION < 7
        case IS_BOOL:
            swParam_bool(Z_BVAL_P(value));
            break;
#else
        case IS_TRUE:
            swParam_bool(1);
            break;
        case IS_FALSE:
            swParam_bool(0);
            break;
#endif
        default:
            swWarn("unknown type.");
            RETURN_FALSE;
        }
    SW_HASHTABLE_FOREACH_END();

    swString *args = swString_dup2(SwooleG.call_php_func_args);
    if (args == NULL)
    {
        return;
    }
    swVal *retval = func(module, args, Z_ARRVAL_P(params)->nNumOfElements);
    if (swVal_to_zval(retval, return_value) < 0)
    {
        RETURN_NULL();
    }
}

static swVal* swoole_call_php_func(const char *name, int length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int i;
    zval **args[SW_PHP_FUNCTION_MAX_ARG];
    zval *zval_array[SW_PHP_FUNCTION_MAX_ARG];
#if PHP_MAJOR_VERSION >= 7
    zval _zval_array[SW_PHP_FUNCTION_MAX_ARG];
#endif
    zval *arg;

    uint32_t offset = 0;
    swVal *val;
    void *params = SwooleG.call_php_func_args->str;

    for (i = 0; i < SwooleG.call_php_func_argc; i++)
    {
#if PHP_MAJOR_VERSION >= 7
        zval_array[i] = &_zval_array[i];
#else
        SW_ALLOC_INIT_ZVAL(zval_array[i]);
#endif
        arg = zval_array[i];
        val = params + offset;
        if (swVal_to_zval(val, arg) < 0)
        {
            return NULL;
        }
        args[i] = &zval_array[i];
        offset += sizeof(swVal) + val->length;
    }

    zval *func_name;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(func_name);
    SW_ZVAL_STRING(func_name, name, 1);

    if (sw_call_user_function_ex(EG(function_table), NULL, func_name, &retval, SwooleG.call_php_func_argc, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_server: onPipeMessage handler error");
        return NULL;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    //clear input buffer
    swArgs_clear();
    for (i = 0; i < SwooleG.call_php_func_argc; i++)
    {
        sw_zval_ptr_dtor(&zval_array[i]);
    }
    //return value
    if (!retval)
    {
        return NULL;
    }
    swVal *val_c = NULL;
    switch(Z_TYPE_P(retval))
    {
#if PHP_MAJOR_VERSION < 7
    case IS_BOOL:
        val_c = sw_malloc(sizeof(swVal) + 1);
        swVal_bool(val_c, Z_BVAL_P(retval));
        break;
#else
    case IS_TRUE:
        val_c = sw_malloc(sizeof(swVal) + 1);
        swVal_bool(val_c, 1);
        break;
    case IS_FALSE:
        val_c = sw_malloc(sizeof(swVal) + 1);
        swVal_bool(val_c, 0);
        break;
#endif
    case IS_STRING:
        val_c = sw_malloc(sizeof(swVal) + Z_STRLEN_P(retval) + 1);
        swVal_string(val_c, Z_STRVAL_P(retval) , Z_STRLEN_P(retval));
        break;
    case IS_LONG:
        val_c = sw_malloc(sizeof(swVal) + sizeof(long));
        swVal_long(val_c, Z_LVAL_P(retval));
        break;
    case IS_DOUBLE:
        val_c = sw_malloc(sizeof(swVal) + sizeof(double));
        swVal_double(val_c, Z_DVAL_P(retval));
        break;
    case IS_NULL:
        return NULL;
    default:
        swWarn("unknown type.");
        break;
    }
    sw_zval_ptr_dtor(&retval);
    return val_c;
}
