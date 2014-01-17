swoole扩展编译安装
=====
Swoole扩展是按照php标准扩展构建的。使用phpize来生成php编译配置，./configure来做编译配置检测，make和make install来完成安装。


```shell
cd swoole
phpize
./configure
make && make install
```

如果已经安装好了 pecl ，可以使用 pecl 安装，推荐使用这种方法。

```shell
pecl install swoole
``

编译安装完成之后，修改php.ini加入extension=swoole.so启用swoole扩展。通过  

```shell
php -m

[PHP Modules]
...
sockets
SPL
standard
swoole
sysvmsg
sysvsem
sysvshm
zlib
...
```
查看php扩展模块中是否有swoole，有的话表示已安装成功。

```shell
cd examples/
php server.php 
```

使用telnet来测试Server是否正常运行

```shell
telnet 127.0.0.1 9501
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
hello world
Swoole: hello world
```


额外：
-----
* 修改swoole_config.h可以调整swoole的某些编译选项，启动某些实验性的特性，或者开启debug
* ./configure --enable-swoole-debug参数用来开启swoole的debug模式，在此模式下，会打印出所有trace信息
* 提示未找到-lrt或pthread_create不存在怎么办？请手工修改Makefile，去掉-lrt/增加-lpthread


