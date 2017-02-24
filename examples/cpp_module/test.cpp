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

Variant cpp_hello_world(Args &args);
Variant cpp_test(Args &params);
Variant CppClass_construct(Object &_this, Args &args);

Variant CppClass_test(Object &_this, Args &args);
Variant CppClass_test2(Object &_this, Args &args);
Variant CppClass_count(Object &_this, Args &args);

int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
int dispatch_function(swServer *serv, swConnection *conn, swEventData *data);

int swModule_init(swModule *module)
{
    module->name = (char *) "test";
    swModule_register_global_function((char *) "test_get_length", (void *) test_get_length);
    swModule_register_global_function((char *) "my_dispatch_function", (void *) dispatch_function);

    PHP::registerFunction(function(cpp_hello_world));
    PHP::registerFunction(function(cpp_test));
    PHP::registerConstant("CPP_CONSTANTS_INT", 1234);

    Array array;
    array.append("127.0.0.1");
    array.append(6379);

    PHP::registerConstant("CPP_CONSTANTS_ARRAY", array);

    string str("test");
    PHP::registerConstant("CPP_CONSTANTS_STRING", str);

    printf("SWOOLE_BASE=%ld\n", PHP::constant("SWOOLE_BASE").toInt());
    printf("swoole_table::TYPE_INT=%ld\n", PHP::constant("swoole_table::TYPE_INT").toInt());

    Class c("CppClass");
    /**
     * 注册构造方法
     */
    c.addMethod("__construct", CppClass_construct, CONSTRUCT);
    /**
     * 普通方法
     */
    c.addMethod("test2", CppClass_test2);
    /**
     * 静态方法
     */
    c.addMethod("test", CppClass_test, STATIC);
    /**
     * 实现接口
     */
    c.implements("Countable");
    c.addMethod("count", CppClass_count);
    /**
     * 添加默认属性
     */
    c.addProperty("name", 1234);
    /**
     * 添加常量
     */
    c.addConstant("VERSION", "1.9.0");
    /**
     * 读取全局变量
     */
    Variant server = PHP::getGlobalVariant("_SERVER");
    if (server.isArray())
    {
      Variant shell = Array(server)["SHELL"];
      var_dump(shell);
    }
    /**
     * 激活类
     */
    c.activate();

    return SW_OK;
}

int test_get_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
{
    printf("cpp, size=%d\n", length);
    return 100;
}

int dispatch_function(swServer *serv, swConnection *conn, swEventData *data)
{
    printf("cpp, type=%d, size=%d\n", data->info.type, data->info.len);
    return data->info.len % serv->worker_num;
}

void testRedis()
{
    cout << "=====================Test Redis==================\n";
    Object redis = PHP::create("redis");
    Array args;
    args.append("127.0.0.1");
    args.append(6379);
    auto ret = redis.call("connect", args);

    Array args2;
    args2.append("key");
    Variant ret2 = redis.call("get", args2);
    printf("value=%s\n", ret2.toCString());
}

Variant CppClass_construct(Object &_this, Args &args)
{
    printf("%s _construct\n", _this.getClassName().c_str());
    Array arr;
    arr.append(1234);
    _this.set("name", arr);
    return nullptr;
}

Variant CppClass_test(Object &_this, Args &args)
{
    printf("CppClass static method call\n");
    //静态方法, _this为null
    //var_dump(_this);
    //var_dump(args);
    return "3.1415926";
}

Variant CppClass_test2(Object &_this, Args &args)
{
    printf("CppClass method call\n");
    //var_dump(_this);
    //var_dump(args);
    return "3.1415926";
}

Variant CppClass_count(Object &_this, Args &args)
{
    return 1;
}

Variant cpp_hello_world(Args &args)
{
    //printf("cpp function call\n");
    //var_dump(args);
    return 3.1415926;
}

/**
 * $module = swoole_load_module(__DIR__.'/test.so');
 * cpp_test("abc", 1234, 459.55, "hello");
 */
Variant cpp_test(Args &params)
{
    printf("key[0] = %s\n", params[0].toCString());
    printf("key[1] = %ld\n", params[1].toInt());
    printf("key[2] = %f\n", params[2].toFloat());
    if (params.count() == 4)
    {
        printf("key[3] = %s\n", params[3].toCString());
    }
    /**
     * 调用PHP代码中的test2函数
     */
    Array array;
    array.append(1234);
    array.append(1234.56);
    array.append(Variant());
    array.append("123456789");
    array.append("tianfenghan");

    Variant retval = PHP::call("test2", array);
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

        if (obj.methodExists("hello"))
        {
            cout << "method [hello] exists\n";
        }
        if (obj.methodExists("abc"))
        {
            cout << "method [abc] exists\n";
        }
        if (obj.propertyExists("name"))
        {
            cout << "property [name] exists\n";
        }
        if (obj.propertyExists("test"))
        {
            cout << "property [test] exists\n";
        }
        Array args2;
        args2.append("Get");
        args2.append("POST");
        args2.append(array);

        Array map;
        map.set("myname", "rango");
        map.set("city", "上海");

        for (auto i = map.begin(); i != map.end(); i++)
        {
            Variant key = i.key();
            Variant value = i.value();
            if (key.isString())
            {
                printf("key=%s, value=%s\n", key.toCString(), value.toCString());
            }
            else
            {
                printf("key=%ld,\n", key.toInt());
            }
        }

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

        testRedis();
    }
    else
    {
        cout << "return value=" << retval.toString() << endl;
    }

    return Variant("hello");
}
