压力测试
=====
通过ab工具分别压测nginx swoole node.js golang的http server，并观察结果。
web server都是输出一行It work!
硬件环境是一台8G/4核酷睿I5CPU的笔记本电脑，型号是Thinkpad T430.

```
Nginx   ab -c 100 -n 100000 http://localhost/index.html
Swoole  ab -c 100 -n 100000 http://127.0.0.1:8848/
Node.js ab -c 100 -n 100000 http://127.0.0.1:8080/
Golang  ab -c 100 -n 100000 http://127.0.0.1:8080/
```

本次测试使用的软件版本如下：
```
nginx version: nginx/1.2.6 (Ubuntu)
go version go1.1.1 linux/amd64
swoole-1.5.4
node.js-0.11.3-pre
```

代码在./code目录中。

QPS对比
-----
```
Nginx:      Requests per second:    23770.74 [#/sec] (mean)
Golang:     Requests per second:    21807.00 [#/sec] (mean)
Swoole:     Requests per second:    19711.22 [#/sec] (mean)
Node.js:    Requests per second:    6680.53 [#/sec] (mean)
```

内存占用对比
-----
Golang 运行多次压测后内存从292K上升至558K，再继续压测不会上升

Node.js运行多次后内存一直在涨，怀疑有内存泄露。从开始运行的593K，到最后的606K。

Nginx的4个worker进程，内存占用一直稳定在82K。

Swoole的主进程内存占用一直稳定在320K，多次压测内存占用没有任何增加。Worker进程的内在占用一直在增加。

通过设置Swoole的max_request参数，worker进程的生命周期是可以控制的，生命周期结束后会自动回收所有内存，所以轻微的内存泄露问题也不大。

结果评价
-----
Nginx、Golang、Swoole都是多线程Reactor的，可以充分利用多核，所以成绩是node.js的数倍。
Swoole中的PHP代码需要编译为opcode来执行，效率比Nginx,Golang这种编译型的语言差一些。
Node.js的http模块不是多线程的，无法利用多核。结果垫底。
