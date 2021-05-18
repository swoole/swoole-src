[English](./ISSUE.md) | 中文

错误报告
===========

# 需知

当你觉得发现了一个Swoole内核的BUG时, 请提出报告.
Swoole的内核开发者们或许还不知道问题的存在,
除非你主动提出报告, 否则BUG也许将很难被发现并修复,
你可以在[Github的issue区](https://github.com/swoole/swoole-src/issues)提出错误报告(即点击右上角绿色的`New issue`按钮), 这里的错误报告将会被最优先解决.
请不要在邮件列表或私人信件中发送错误报告, GitHub的issue区同样可以提出对于Swoole的任何要求与建议.

在你提交错误报告之前, 请先阅读以下的**如何提交错误报告**.

## 新建问题

首先在创建issue的同时, 系统将会给出如下模板, 请你认真填写它, 否则issue由于缺乏信息可能会被忽略:

```markdown

Please answer these questions before submitting your issue. Thanks!
> 在提交Issue前请回答以下问题：

1. What did you do? If possible, provide a simple script for reproducing the error.
> 请详细描述问题的产生过程，贴出相关的代码，最好能提供一份可稳定重现的简单脚本代码。

2. What did you expect to see?
> 期望的结果是什么？

3. What did you see instead?
> 实际运行的结果是什么？

4. What version of Swoole are you using (`php --ri swoole`)?
> 你的版本? 贴出 `php --ri swoole` 所打印的内容

5. What is your machine environment used (including the version of kernel & php & gcc)?
> 你使用的机器系统环境是什么（包括内核、PHP、gcc编译器版本信息）？
> 可以使用`uname -a`, `php -v`, `gcc -v` 命令打印

```

其中, 最为关键的是提供**可稳定重现的简单脚本代码**, 否则你必须提供尽可能多的其它信息来帮助开发者判断错误原因

## 内存分析 (强烈推荐)

更多时候, Valgrind比gdb更能发现内存问题, 通过以下指令运行你的程序, 直到触发BUG

```shell
USE_ZEND_ALLOC=0 valgrind --log-file=/tmp/valgrind.log php your_file.php
```

* 当程序发生错误时, 可以通过键入 `ctrl+c` 退出, 然后上传 `/tmp/valgrind.log` 文件以便于开发组定位BUG.

## 关于段错误(核心转储)

此外, 在一种特殊情况下你可以使用调试工具来帮助开发者定位问题

```shell
WARNING	swManager_check_exit_status: worker#1 abnormal exit, status=0, signal=11
```

当如上提示出现在Swoole日志中(signal11), 说明程序发生了`核心转储`, 你需要使用跟踪调试工具来确定其发生位置

> 使用`gdb`来跟踪`swoole`前, 需要在编译时添加`--enable-debug`参数以保留更多信息

开启核心转储文件
```shell
ulimit -c unlimited
```

触发BUG, 核心转储文件会生成在 程序目录 或 系统根目录 或 `/cores` 目录下 (取决于你的系统配置), 键入以下命令进入gdb调试程序
```
gdb php core
gdb php /tmp/core.4596
```

紧接着输入`bt`并回车, 就可以看到出现问题的调用栈
```
(gdb) bt
```

可以通过键入 `f 数字` 来查看指定的调用栈帧
```
(gdb)f 1
(gdb)f 0
```

将以上信息都贴在issue中
