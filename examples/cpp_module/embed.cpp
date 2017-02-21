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

#include "PHP_embed.hpp"

#include <iostream>

using namespace PHP;
using namespace std;

int main(int argc, char * argv[])
{
    PHP::VM vm(argc, argv);
    vm.eval("echo 'Hello World!';");
    vm.include("embed.php");

    auto a = constant("SWOOLE_BASE");
    cout << "SWOOLE_BASE = " << a.toInt() << endl;

    auto obj = PHP::create("Test");
    auto ret = obj.call("getName");

    cout << ret.toString() << endl;

    obj.set("name", "Tianfeng");

    auto ret2 = obj.call("getName");
    cout << ret2.toString() << endl;

    return 0;
}
