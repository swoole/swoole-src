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

#pragma once

extern "C"
{
#include "sapi/embed/php_embed.h"
}

#include "phpx.h"

namespace php
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
    void eval(const char *script)
    {
        std::string s(script);
        eval(s);
    }
    void eval(std::string &script)
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
    inline Variant include(std::string file)
    {
        return include(file);
    }
    int exit_status;
private:
    std::string program_name;
};
}

