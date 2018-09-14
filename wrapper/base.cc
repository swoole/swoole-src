/*
  +----------------------------------------------------------------------+
  | PHP-X                                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 The Swoole Group                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the GPL license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.gnu.org/licenses/                                         |
  | If you did not receive a copy of the GPL3.0 license and are unable   |
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "phpx.h"

using namespace std;

namespace php
{

unordered_map<string, Resource *> resource_map;
unordered_map<string, Class*> class_map;
unordered_map<string, Interface*> interface_map;
map<const char *, map<const char *, method_t, strCmp>, strCmp> method_map;
map<const char *, function_t, strCmp> function_map;
map<int, void *> object_array;
unordered_map<string, Extension*> _name_to_extension;
unordered_map<int, Extension*> _module_number_to_extension;

void error(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    php_verror(NULL, "", level, format, args);
    va_end(args);
}

Variant constant(const char *name)
{
    zend_string *_name = zend_string_init(name, strlen(name), 0);
    zval *val = zend_get_constant_ex(_name, NULL, ZEND_FETCH_CLASS_SILENT);
    zend_string_free(_name);
    if (val == NULL)
    {
        return nullptr;
    }
    Variant retval(val);
    return retval;
}

void echo(const char *format, ...)
{
    va_list args;
    char *buffer;
    size_t size;

    va_start(args, format);
    size = vspprintf(&buffer, 0, format, args);
    PHPWRITE(buffer, size);
    efree(buffer);
    va_end(args);
}

static int validate_constant_array(HashTable *ht) /* {{{ */
{
    int ret = 1;
    zval *val;

    ht->u.v.nApplyCount++;
    ZEND_HASH_FOREACH_VAL_IND(ht, val)
    {
        ZVAL_DEREF(val);
        if (Z_REFCOUNTED_P(val))
        {
            if (Z_TYPE_P(val) == IS_ARRAY)
            {
                if (Z_REFCOUNTED_P(val))
                {
                    if (Z_ARRVAL_P(val)->u.v.nApplyCount > 0)
                    {
                        zend_error(E_WARNING, "Constants cannot be recursive arrays");
                        ret = 0;
                        break;
                    }
                    else if (!validate_constant_array(Z_ARRVAL_P(val)))
                    {
                        ret = 0;
                        break;
                    }
                }
            }
            else if (Z_TYPE_P(val) != IS_STRING && Z_TYPE_P(val) != IS_RESOURCE)
            {
                zend_error(E_WARNING, "Constants may only evaluate to scalar values or arrays");
                ret = 0;
                break;
            }
        }
    }
    ZEND_HASH_FOREACH_END();
    ht->u.v.nApplyCount--;
    return ret;
}

static void copy_constant_array(zval *dst, zval *src) /* {{{ */
{
    zend_string *key;
    zend_ulong idx;
    zval *new_val, *val;

    array_init_size(dst, zend_hash_num_elements(Z_ARRVAL_P(src)));
    ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL_P(src), idx, key, val)
    {
        /* constant arrays can't contain references */
        ZVAL_DEREF(val);
        if (key)
        {
            new_val = zend_hash_add_new(Z_ARRVAL_P(dst), key, val);
        }
        else
        {
            new_val = zend_hash_index_add_new(Z_ARRVAL_P(dst), idx, val);
        }
        if (Z_TYPE_P(val) == IS_ARRAY)
        {
            if (Z_REFCOUNTED_P(val))
            {
                copy_constant_array(new_val, val);
            }
        }
        else if (Z_REFCOUNTED_P(val))
        {
            Z_ADDREF_P(val);
        }
    }
    ZEND_HASH_FOREACH_END();
}

bool define(const char *name, const Variant &v, bool case_sensitive)
{
    size_t len = strlen(name);
    zval *val = const_cast<Variant &>(v).ptr(), val_free;
    zend_constant c;

    /* class constant, check if there is name and make sure class is valid & exists */
    if (zend_memnstr(name, "::", sizeof("::") - 1, name + len))
    {
        zend_error(E_WARNING, "Class constants cannot be defined or redefined");
        return false;
    }

    ZVAL_UNDEF(&val_free);

    repeat: switch (Z_TYPE_P(val))
    {
    case IS_LONG:
    case IS_DOUBLE:
    case IS_STRING:
    case IS_FALSE:
    case IS_TRUE:
    case IS_NULL:
    case IS_RESOURCE:
        break;
    case IS_ARRAY:
        if (Z_REFCOUNTED_P(val))
        {
            if (!validate_constant_array(Z_ARRVAL_P(val)))
            {
                return false;
            }
            else
            {
                copy_constant_array(&c.value, val);
                goto register_constant;
            }
        }
        break;
    case IS_OBJECT:
        if (Z_TYPE(val_free) == IS_UNDEF)
        {
            if (Z_OBJ_HT_P(val)->get)
            {
                zval rv;
                val = Z_OBJ_HT_P(val)->get(val, &rv);
                ZVAL_COPY_VALUE(&val_free, val);
                goto repeat;
            }
            else if (Z_OBJ_HT_P(val)->cast_object)
            {
                if (Z_OBJ_HT_P(val)->cast_object(val, &val_free, IS_STRING) == SUCCESS)
                {
                    val = &val_free;
                    break;
                }
            }
        }
        /* no break */
    default:
        zend_error(E_WARNING, "Constants may only evaluate to scalar values or arrays");
        zval_ptr_dtor(&val_free);
        return false;
    }

    ZVAL_COPY(&c.value, val);
    zval_ptr_dtor(&val_free);
    register_constant: c.flags = case_sensitive ? CONST_CS : 0; /* non persistent */
    c.name = zend_string_init(name, len, 0);
    c.module_number = PHP_USER_CONSTANT;
    if (zend_register_constant(&c) == SUCCESS)
    {
        return true;
    }
    else
    {
        return false;
    }
}

String number_format(double num, int decimals, char dec_point, char thousands_sep)
{
    return _php_math_number_format(num, decimals, dec_point, thousands_sep);
}

int extension_startup(int type, int module_number)
{
    zend_module_entry *module;
    void *ptr;
    ZEND_HASH_FOREACH_PTR(&module_registry, ptr)
    {
        module = (zend_module_entry *) ptr;
        if (module_number == module->module_number)
        {
            Extension *extension = _name_to_extension[module->name];
            extension->started = true;
            extension->registerIniEntries(module_number);
            if (extension->onStart)
            {
                extension->onStart();
            }
            _module_number_to_extension[module_number] = extension;
            break;
        }
    }
    ZEND_HASH_FOREACH_END();
    return SUCCESS;
}

void extension_info(zend_module_entry *module)
{
    Extension *extension = _module_number_to_extension[module->module_number];
    if (extension->header.size() > 0 && extension->body.size() > 0)
    {
        php_info_print_table_start();
        auto header = extension->header;
        size_t size = header.size();
        switch (size)
        {
        case 2:
            php_info_print_table_header(size, header[0].c_str(), header[1].c_str());
            break;
        case 3:
            php_info_print_table_header(size, header[0].c_str(), header[1].c_str(), header[2].c_str());
            break;
        default:
            error(E_WARNING, "invalid info header size.");
            return;
        }
        for (auto row : extension->body)
        {
            size = row.size();
            switch (size)
            {
            case 2:
                php_info_print_table_row(size, row[0].c_str(), row[1].c_str());
                break;
            case 3:
                php_info_print_table_row(size, row[0].c_str(), row[1].c_str(), row[2].c_str());
                break;
            default:
                error(E_WARNING, "invalid info row size.");
                return;
            }
        }
        php_info_print_table_end();
    }
}

int extension_shutdown(int type, int module_number)
{
    Extension *extension = _module_number_to_extension[module_number];
    if (extension->onShutdown)
    {
        extension->onShutdown();
    }
    extension->unregisterIniEntries(module_number);
    _name_to_extension.erase(extension->name);
    _module_number_to_extension.erase(module_number);
    delete extension;

    return SUCCESS;
}

int extension_before_request(int type, int module_number)
{
    Extension *extension = _module_number_to_extension[module_number];
    if (extension->onBeforeRequest)
    {
        extension->onBeforeRequest();
    }

    return SUCCESS;
}

int extension_after_request(int type, int module_number)
{
    Extension *extension = _module_number_to_extension[module_number];
    if (extension->onAfterRequest)
    {
        extension->onAfterRequest();
    }

    return SUCCESS;
}

static inline ZEND_RESULT_CODE _check_args_num(zend_execute_data *data, int num_args)
{
    uint32_t min_num_args = data->func->common.required_num_args;
    uint32_t max_num_args = data->func->common.num_args;

    if (num_args < min_num_args || (num_args > max_num_args && max_num_args > 0))
    {
#if PHP_MINOR_VERSION == 0
        zend_wrong_paramers_count_error(num_args, min_num_args, max_num_args);
#elif PHP_MINOR_VERSION == 1
        zend_wrong_parameters_count_error(num_args, min_num_args, max_num_args);
#else
        zend_wrong_parameters_count_error(1, num_args, min_num_args, max_num_args);
#endif
        return FAILURE;
    }

    return SUCCESS;
}

void _exec_function(zend_execute_data *data, zval *return_value)
{
    function_t func = function_map[(const char *) data->func->common.function_name->val];
    Args args;

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    if (_check_args_num(data, arg_count) == FAILURE)
    {
        return;
    }

    while (arg_count-- > 0)
    {
        args.append(param_ptr);
        param_ptr++;
    }
    Variant _retval(return_value, true);
    func(args, _retval);
}

void _exec_method(zend_execute_data *data, zval *return_value)
{
    method_t func = method_map[(const char *) data->func->common.scope->name->val][(const char *) data->func->common.function_name->val];
    Args args;

    Object _this(&data->This, true);

    zval *param_ptr = ZEND_CALL_ARG(EG(current_execute_data), 1);
    int arg_count = ZEND_CALL_NUM_ARGS(EG(current_execute_data));

    if (_check_args_num(data, arg_count) == FAILURE)
    {
        return;
    }

    while (arg_count-- > 0)
    {
        args.append(param_ptr);
        param_ptr++;
    }
    Variant _retval(return_value, true);
    func(_this, args, _retval);
}

Variant _call(zval *object, zval *func, Args &args)
{
    Variant retval;
    zval params[PHPX_MAX_ARGC];
    for (int i = 0; i < args.count(); i++)
    {
        ZVAL_COPY_VALUE(&params[i], args[i].ptr());
    }
    if (call_user_function(EG(function_table), object, func, retval.ptr(), args.count(), params) == SUCCESS)
    {
        return retval;
    }
    else
    {
        return nullptr;
    }
}

Variant _call(zval *object, zval *func)
{
    Variant retval = false;
    if (call_user_function(EG(function_table), object, func, retval.ptr(), 0, NULL) == 0)
    {
        return retval;
    }
    else
    {
        return nullptr;
    }
}

Variant include(string file)
{
    zend_file_handle file_handle;
    int ret = php_stream_open_for_zend_ex(file.c_str(), &file_handle, USE_PATH | STREAM_OPEN_FOR_INCLUDE);
    if (ret != SUCCESS)
    {
        return false;
    }

    zend_string *opened_path;
    if (!file_handle.opened_path)
    {
        file_handle.opened_path = zend_string_init(file.c_str(), file.length(), 0);
    }
    opened_path = zend_string_copy(file_handle.opened_path);
    zval dummy;
    Variant retval = false;
    zend_op_array *new_op_array;
    ZVAL_NULL(&dummy);
    if (zend_hash_add(&EG(included_files), opened_path, &dummy))
    {
        new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE);
        zend_destroy_file_handle(&file_handle);
    }
    else
    {
        new_op_array = NULL;
        zend_file_handle_dtor(&file_handle);
    }
    zend_string_release(opened_path);
    if (!new_op_array)
    {
        return false;
    }

    ZVAL_UNDEF(retval.ptr());
    zend_execute(new_op_array, retval.ptr());

    destroy_op_array(new_op_array);
    efree(new_op_array);
    return retval;
}

}
