# 扩展冲突

由于某些跟踪调试的`PHP`扩展大量使用了全局变量，可能会导致`Swoole`协程发生崩溃。请关闭以下相关扩展：

* xdebug
* phptrace
* aop
* molten
* xhprof
* phalcon（`Swoole`协程无法运行在 `phalcon` 框架中）

~~其中`xdebug`和`phptrace`可以用 [sdebug](https://github.com/swoole/sdebug) 代替，[点击查看安装说明](/question/install?id=安装xdebug)；~~

!> 推荐使用 [Yasd](https://github.com/swoole/yasd) 进行 Swoole 调试，类似 Xdebug，完美支持协程，支持断点调试、单步追踪、watch 变量；

`xhprof`、`blackfire`和`molten`可以用 [Swoole Tracker](https://business.swoole.com/tracker/index) 代替。