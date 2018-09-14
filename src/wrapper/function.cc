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

Variant http_build_query(const Variant &data, const char* prefix, const char* arg_sep, int enc_type)
{
    smart_str formstr =
    { 0 };

    Variant &_data = const_cast<Variant &>(data);
    if (!_data.isArray() && !_data.isObject())
    {
        error(E_WARNING, "Parameter 1 expected to be Array or Object.  Incorrect value given");
        return false;
    }

    size_t prefix_len = prefix != nullptr ? strlen(prefix) : 0;
    if (php_url_encode_hash_ex(HASH_OF(_data.ptr()), &formstr, prefix, prefix_len, NULL, 0, NULL, 0,
            (_data.isObject() ? _data.ptr() : NULL), (char *) arg_sep, enc_type) == FAILURE)
    {
        if (formstr.s)
        {
            smart_str_free(&formstr);
        }
        return false;
    }

    if (!formstr.s)
    {
        return "";
    }

    smart_str_0(&formstr);
    return formstr.s;
}

}


