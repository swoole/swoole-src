swoole_server_start函数
-----
启动server，监听所有TCP/UDP端口，函数原型：
```php
bool swoole_server_start(resource $serv)
```
启动失败扩展内会抛出致命错误，请检查php error_log的相关信息。errno={number}是标准的Linux Errno，可参考相关文档。  
如果开启了log_file设置，信息会打印到制定的Log文件中。

常见的错误有：
-----
* bind端口失败,原因是其他进程已占用了此端口
* php有代码致命错误，请检查php的错误信息


