使用swoole作为C代码Server框架
===========
swoole使用cmake来做编译配置，示例程序在examples/server.c中。
您可以在此基础上进行代码开发。
如果需要修改编译细节的选项，请直接修改CMakeLists.txt

Build & Install
-----
```bash
cmake .
make
make install
```

Example
-----
源代码编写请参考examples/server.c
只需要引入swoole头即可。
```c
#include <swoole/Server.h>
#include <swoole/Client.h>
```
编译运行
```
gcc -o server server.c -lswoole
./server
```

