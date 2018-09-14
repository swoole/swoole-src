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

/*generator*/
Variant exec(const char *func, const Variant &v1)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    args.append(const_cast<Variant &>(v6).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    args.append(const_cast<Variant &>(v6).ptr());
    args.append(const_cast<Variant &>(v7).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    args.append(const_cast<Variant &>(v6).ptr());
    args.append(const_cast<Variant &>(v7).ptr());
    args.append(const_cast<Variant &>(v8).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    args.append(const_cast<Variant &>(v6).ptr());
    args.append(const_cast<Variant &>(v7).ptr());
    args.append(const_cast<Variant &>(v8).ptr());
    args.append(const_cast<Variant &>(v9).ptr());
    return _call(NULL, _func.ptr(), args);
}

Variant exec(const char *func, const Variant &v1, const Variant &v2, const Variant &v3, const Variant &v4, const Variant &v5, const Variant &v6, const Variant &v7, const Variant &v8, const Variant &v9, const Variant &v10)
{
    Variant _func(func);
    Args args;
    args.append(const_cast<Variant &>(v1).ptr());
    args.append(const_cast<Variant &>(v2).ptr());
    args.append(const_cast<Variant &>(v3).ptr());
    args.append(const_cast<Variant &>(v4).ptr());
    args.append(const_cast<Variant &>(v5).ptr());
    args.append(const_cast<Variant &>(v6).ptr());
    args.append(const_cast<Variant &>(v7).ptr());
    args.append(const_cast<Variant &>(v8).ptr());
    args.append(const_cast<Variant &>(v9).ptr());
    args.append(const_cast<Variant &>(v10).ptr());
    return _call(NULL, _func.ptr(), args);
}
/*generator*/

}
