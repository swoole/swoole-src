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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

extern "C"
{
#include "sapi/embed/php_embed.h"
}

#include "PHP_API.hpp"

namespace PHP
{
class VM
{
public:
    VM(int argc, char ** argv)
    {
        php_embed_init(argc, argv);
        exit_status = 0;
        program_name = argv[0];
    }
    ~VM()
    {
        php_embed_shutdown();
    }
    void eval(char *script)
    {
        string s(script);
        eval(s);
    }
    void eval(string &script)
    {
        zend_first_try
        {
            zend_eval_stringl((char *) script.c_str(), script.length(), NULL, (char *) program_name.c_str());
        }
        zend_catch
        {
            exit_status = EG(exit_status);
        }
        zend_end_try();
    }
    bool include(string file)
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
        zval result;
        zend_op_array *new_op_array;
        ZVAL_NULL(&dummy);
        if (zend_hash_add(&EG(included_files), opened_path, &dummy))
        {
            new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE);
            zend_destroy_file_handle (&file_handle);
        }
        else
        {
            new_op_array = NULL;
            zend_file_handle_dtor (&file_handle);
        }
        zend_string_release(opened_path);
        if (!new_op_array)
        {
            return false;
        }

        ZVAL_UNDEF(&result);
        zend_execute(new_op_array, &result);

        destroy_op_array(new_op_array);
        efree(new_op_array);
        if (!EG(exception))
        {
            zval_ptr_dtor(&result);
        }
        return true;
    }
    int exit_status;
private:
    string program_name;
};
}

