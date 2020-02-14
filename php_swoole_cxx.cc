#include "php_swoole_cxx.h"

bool zend::include(std::string file)
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

    zval retval;
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

    zend_execute(new_op_array, &retval);

    destroy_op_array(new_op_array);
    efree(new_op_array);
    return Z_TYPE(retval) == IS_TRUE;
}

//for compatibly with dis_eval
zend_op_array* (*old_compile_string)(zval *source_string, ZEND_STR_CONST char *filename);

zend_op_array* zend::swoole_compile_string(zval *source_string, ZEND_STR_CONST char *filename)
{
    zend_op_array *opa = old_compile_string(source_string, filename);
    opa->type = ZEND_USER_FUNCTION;
    return opa;
}


bool zend::eval(std::string code, std::string filename)
{
    if (!old_compile_string)
    {
        old_compile_string = zend_compile_string;
    }
    //overwrite
    zend_compile_string = swoole_compile_string;
    int ret = (zend_eval_stringl((char*) code.c_str(), code.length(), nullptr, (char *) filename.c_str()) == SUCCESS);
    //recover
    zend_compile_string = old_compile_string;
    return ret;
}
