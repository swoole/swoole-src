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

#include <string>
#include <iostream>

using namespace std;

extern "C"
{
    #include "swoole.h"
    #include "module.h"
    int swModule_init(swModule *);
}

swVal* cppMethod(swModule *module, swString *args, int argc);

int swModule_init(swModule *module)
{
    module->name = (char *) "test";

    string s = "123456789";
    string php_func = "test";

    swParam_long(1234);
    swParam_double(1234.56);
    swParam_string(s.c_str(), s.length());

    swModule_register_function(module, (char *) "cppMethod", cppMethod);

    swVal* a = SwooleG.call_php_func(php_func.c_str(), php_func.length());

    return SW_OK;
}

/**
 * $module = swoole_load_module(__DIR__.'/test.so');
 * $module->cppMethod("abc", 1234, 459.55, "hello");
 */
swVal* cppMethod(swModule *module, swString *args, int argc)
{
    cout << "hello world" << endl;

    int l_a, l_d;
    char *a = swParam_parse_string(args, &l_a);
    long b = swParam_parse_long(args);
    double c = swParam_parse_double(args);
    char *d = swParam_parse_string(args, &l_d);

    char buf[256];
    int len = snprintf(buf, sizeof(buf), "a[%d]=%s, b=%ld, c=%f, d[%d]=%s\n", l_a, a, b, c, l_d, d);
    return swReturnValue_string(buf, len);
}
