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
#include "swoole.h"
#include "module.h"

using namespace std;

extern "C"
{
    int swModule_init(swModule *);
}

swVal* cppMethod(swModule *module, int argc);
int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);

int swModule_init(swModule *module)
{
    printf("cpp module init\n");
    module->name = (char *) "test";

    string s = "123456789";
    string php_func = "test";

    swArgs_push_long(1234);
    swArgs_push_double(1234.56);
    swArgs_push_string(s.c_str(), s.length());

    swModule_register_function(module, (char *) "cppMethod", cppMethod);
    swModule_register_global_function((char *) "test_get_length", (void *) test_get_length);

//    int ret = SwooleG.call_php_func(php_func.c_str());
//    if (ret < 0)
//    {
//        cout << "call php function failed." << endl;
//    }
//    else if (ret > 0)
//    {
//        int length;
//        cout << "return value type=" << ret << ", value=" <<  swReturnValue_get_string(&length) << endl;
//    }
    return SW_OK;
}

int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
{
    printf("cpp, size=%d\n", length);
    return 100;
}

/**
 * $module = swoole_load_module(__DIR__.'/test.so');
 * $module->cppMethod("abc", 1234, 459.55, "hello");
 */
swVal* cppMethod(swModule *module, int argc)
{
    int l_a, l_d;
    char *a = swArgs_pop_string(&l_a);
    long b = swArgs_pop_long();
    double c = swArgs_pop_double();
    char *d = swArgs_pop_string(&l_d);

    return swReturnValue_long(1234);

    //char buf[256];
    //int len = snprintf(buf, sizeof(buf), "a[%d]=%s, b=%ld, c=%f, d[%d]=%s\n", l_a, a, b, c, l_d, d);
    //return swReturnValue_string(buf, len);
}
