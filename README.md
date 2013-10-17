Introduction
==========

Swoole written by C, based on the Linux epoll does not rely on any third-party libraries, as a the PHP extensions running high-performance network server framework, you can easily maintain more than 100,000 concurrent TCP connections. Swoole provides a full asynchronous, non-blocking, parallel PHP Socket Server to achieve. Support UDP, TCP, IPv6 support multi-port monitoring, multi timer and operation mode can be configured.
PHP developers do not care about the underlying implementation, only need to use PHP to write the callback function, write the logic code can be. Swoole can be used for server-side development, such as WebSocket Server, Web server, FTP server.

* [Document 中文](http://www4swoole.sinaapp.com/wiki.php) 
* Document English. Wait supplement

Features
-----

* Event-driven
* Full asynchronous non-blocking
* No lock design
* Separate read and write
* Concurrent execution. Support Multi-Thread or Multi-Process
* Support IPv6

Developer Mail-List
-----
* Google Group: <https://groups.google.com/forum/#!forum/swoole>  
* Email: <swoole@googlegroups.com>


For PHP
-----
```shell
cd swoole/
phpize
./configure
make && make install
```

For C/C++
-----
```shell
cd swoole/
cmake .
make && make install
```

PHP Application Server
-----
https://github.com/matyhtf/swoole_framework

Example
-----
* PHP: [examples/server.php](examples/server.php)
* C/C++: [examples/server.c](examples/server.c)
* Client: [examples/client.php](examples/client.php)

License
-----
Apache License Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0.html>



