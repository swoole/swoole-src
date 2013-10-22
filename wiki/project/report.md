错误问题报告
----
当使用swoole发生段错误时，请及时向开发组报告。可以使用gdb工具来得到一份bt信息。

打开core dump
```shell
ulimit -c unlimited
```

使用gdb来查看core dump信息。core文件一般在当前目录，如果操作系统做了处理，将core dump文件放置到其他目录，请替换为相应的路径
```
gdb php core 
gdb php /tmp/core.4596
```

在gdb下输入bt查看调用栈信息
```
(gdb)bt
Program terminated with signal 11, Segmentation fault.
#0  0x00007f1cdbe205e0 in swServer_onTimer (reactor=<value optimized out>, event=...)  
    at /usr/local/php/swoole-swoole-1.5.9b/src/network/Server.c:92
92                              serv->onTimer(serv, timer_node->interval);
Missing separate debuginfos, use: debuginfo-install php-cli-5.3.3-22.el6.x86_64
```

在gdb中使用f指令查看代码段
```
(gdb)f 1
(gdb)f 0
```

请将上面的得到的信息，发送邮件给 <team@swoole.com> . Swoole开发组会很快解决.   
您也可以通过GibHub平台[提交bug](https://github.com/matyhtf/swoole/issues/new)给我们.
