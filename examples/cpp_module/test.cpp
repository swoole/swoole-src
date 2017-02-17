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

#include "PHP_API.hpp"
#include "module.h"

using namespace std;
using namespace PHP;

extern "C"
{
    int swModule_init(swModule *);
}

void cppMethod(swModule *module, zval *_params, zval *_return_value);
int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);

int swModule_init(swModule *module)
{
    module->name = (char *) "test";

    swModule_register_function(module, (char *) "cppMethod", (void *) cppMethod);
    swModule_register_global_function((char *) "test_get_length", (void *) test_get_length);

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
void cppMethod(swModule *module, zval *_params, zval *_return_value)
{
    Array params(_params);
    Variant return_value(_return_value, true);

    printf("key[0] = %s\n", params[0].toCString());
    printf("key[1] = %ld\n", params[1].toInt());
    printf("key[2] = %f\n", params[2].toFloat());
    printf("key[3] = %s\n", params[3].toCString());

    /**
     * 调用PHP代码中的test2函数
     */
    Array args;
    args.append(1234);
    args.append(1234.56);
    args.append("123456789");
    args.append("tianfenghan");

    Variant retval = PHP::call("test2", args);
    /**
     * test2函数返回了数组
     */
    if (retval.isArray())
    {
        //把变量转成数组
        Array arr(retval);
        for (int i = 0; i < arr.count(); i++)
        {
            printf("key[%d] = %s\n", i, arr[i].toString().c_str());
        }
    }
    /**
     * test2函数返回了对象
     */
    else if (retval.isObject())
    {
        //把变量转为对象
        Object obj(retval);

        Array args2;
        args2.append("Get");
        args2.append("POST");
        args2.append(args);

        Array map;
        map.set("myname", "rango");
        map.set("city", "上海");
        args2.append(map);

        /**
         * 设置对象属性
         */
        obj.set("hello", map);

        /**
         * 调用对象的方法
         */
        Variant retval2 = obj.call("abc", args2);
        if (retval2.isArray())
        {
            //把return的变量转成数组
            Array arr2(retval2);
            cout << "key: " << arr2["key"].toString() << ", value: " << arr2["value"].toString() << endl;
        }
        /**
         * 读取对象属性
         */
        Variant name = obj.get("name");
        cout << "name property: " << name.toString() << endl;

        /**
         * 创建一个Test2类的对象
         */
        Object obj2 = PHP::create("Test2", args2);
        /**
         * 调用它的hello方法
         */
        obj2.call("hello");
    }
    else
    {
        cout << "return value=" << retval.toString() << endl;
    }

    return_value = "hello";
    return;
}
