改变Worker进程的用户/组
-----
在某些情况下，主进程需要使用Root来启动，比如需要监听80端口。这时Worker进程的业务代码也会运行在root用户下，这是非常不安全的。
业务代码的漏洞可能会导致整个服务器被攻破，所以需要将Worker进程所属用户和组改为其他用户。
在PHP中使用posix系列函数即可完成此操作。可在swoole的onWorkerStart回调中加入以下代码：

```php
$user = posix_getpwnam('www-data');
posix_setuid($user['uid']);
posix_setgid($user['gid']);
```

重定向根目录
-----
默认是没有重定向的，在PHP代码中访问/etc/目录，就是指文件系统的/etc/，这样是不安全的。比如PHP代码中误操作执行rm -rf /。会带来严重的后果。
可以使用chroot函数，将根目录重定向到另外一个安全的目录。

```php
chroot('/tmp/root/');
```

