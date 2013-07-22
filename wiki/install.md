swoole扩展编译安装
=====
Swoole扩展是按照php标准扩展构建的。使用phpize来生成php编译配置，./configure来做编译配置检测，make和make install来完成安装。
修改php.ini加入extension=swoole.so启用swoole扩展。

额外：
-----
* 修改swoole_config.h可以调整swoole的某些编译选项，启动某些实验性的特性，或者开启debug
* ./configure --enable-swoole-debug参数用来开启swoole的debug模式，在此模式下，会打印出所有trace信息
