# Swoole

?> `Swoole` 是一个使用 `C++` 语言编写的基于异步事件驱动和协程的并行网络通信引擎，为`PHP`提供[协程](/coroutine)、[高性能](/question/use?id=swoole性能如何)网络编程支持。提供了多种通信协议的网络服务器和客户端模块，可以方便快速的实现`TCP/UDP服务`、`高性能Web`、`WebSocket服务`、`物联网`、`实时通讯`、`游戏`、`微服务`等，使`PHP`不再局限于传统的Web领域。

## Swoole类图

!>可以直接点击链接到对应的文档页

[//]: # (https://naotu.baidu.com/file/bd9d2ba7dfae326e6976f0c53f88b18c)

<embed src="_images/swoole_class.svg" type="image/svg+xml" alt="Swoole架构图" />

## 官方网站

* [Swoole](//www.swoole.com)
* [商业支持](//business.swoole.com)
* [问答](//wenda.swoole.com)

## 项目地址

* [GitHub](//github.com/swoole/swoole-src) **（支持请点Star）**
* [码云](//gitee.com/swoole/swoole)
* [Pecl](//pecl.php.net/package/swoole)

## 开发工具

* [IDE Helper](https://github.com/swoole/ide-helper)
* [Yasd](https://github.com/swoole/yasd)
* [debugger](https://github.com/swoole/debugger)
* [sdebug](https://github.com/swoole/sdebug)

## 版权信息

本文档原始内容摘自之前的 [旧版Swoole文档](https://wiki.swoole.com/wiki/index/prid-1)，旨在解决大家一直吐槽的文档问题，采用现代化的文档组织形式，只包含`Swoole4`的内容，修改了大量老文档中错误的内容，优化了文档细节，增加了示例代码和一些教学内容，对`Swoole`新手更友好。

本文档所有内容，包括所有文字、图片和音视频资料，版权均属 **识沃网络科技有限公司** 所有，任何媒体、网站或个人可以以外链的形式引用，但未经协议授权不得以任何形式复制发布/发表。

## 文档发起者

* 杨才 [GitHub](https://github.com/TTSimple)
* 郭新华 [Weibo](https://www.weibo.com/u/2661945152)
* [鲁飞](https://github.com/sy-records) [Weibo](https://weibo.com/5384435686)

## 问题反馈

关于本文档中的内容问题（如错别字、示例错误、内容缺失等）以及需求建议，请统一至 [swoole-inc/report](https://github.com/swoole-inc/report) 项目中提交`issue`，也可直接点击右上角的 [反馈](/?id=main) 跳转至`issue`页面。

一经采纳，将会添加提交者信息至 [文档贡献者](/CONTRIBUTING) 列表当中以示感谢。

## 文档原则

使用直白的语言，**尽量**少介绍`Swoole`底层技术细节和一些底层的概念，底层的后续可以维护一个专门的`hack`章节；

有些概念绕不过去的时候，**必须**有一个集中的地方介绍此概念，其他地方内链过去。例如：[事件循环](/learn?id=什么是eventloop) ；

写文档时要转变思维，以小白的角度去审视别人能不能看得懂；

后续出现功能改动的时候**一定**要把所有涉及的地方都修改一遍，不能只修改一个地方；

每个功能模块**必须**要有一个完整示例；
