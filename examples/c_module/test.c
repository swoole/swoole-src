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

#include "swoole.h"
#include "module.h"

int swModule_init(swModule *);

swVal* cMethod(swModule *module, int argc);
int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);

int swModule_init(swModule *module)
{
    printf("c module init\n");
    module->name = (char *) "test";

    char *s = "123456789";
    char *php_func = "test";

    swArgs_push_long(1234);
    swArgs_push_double(1234.56);
    swArgs_push_string(s, strlen(s));

    swModule_register_function(module, (char *) "cppMethod", cMethod);
    swModule_register_global_function((char *) "test_get_length", test_get_length);

    return SW_OK;
}

int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
{
    printf("c, size=%d\n", length);
    return 100;
}

swVal* cMethod(swModule *module, int argc)
{
    int l_a, l_d;
    char *a = swArgs_pop_string(&l_a);
    long b = swArgs_pop_long();
    double c = swArgs_pop_double();
    char *d = swArgs_pop_string(&l_d);

    return swReturnValue_long(1234);
}
