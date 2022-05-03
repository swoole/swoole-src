# 常量

!> 此处不包含所有常量，如需查看所有常量请访问或安装：[ide-helper](https://github.com/swoole/ide-helper/blob/master/output/swoole/constants.php)

## Swoole

常量 | 作用
---|---
SWOOLE_VERSION | 当前Swoole的版本号，字符串类型，如1.6.0

## 构造方法参数

常量 | 作用
---|---
[SWOOLE_BASE](/learn?id=swoole_base) | 使用Base模式，业务代码在Reactor进程中直接执行
[SWOOLE_PROCESS](/learn?id=swoole_process) | 使用进程模式，业务代码在Worker进程中执行

## Socket 类型

常量 | 作用
---|---
SWOOLE_SOCK_TCP | 创建tcp socket
SWOOLE_SOCK_TCP6 | 创建tcp ipv6 socket
SWOOLE_SOCK_UDP | 创建udp socket
SWOOLE_SOCK_UDP6 | 创建udp ipv6 socket
SWOOLE_SOCK_UNIX_DGRAM | 创建unix dgram socket
SWOOLE_SOCK_UNIX_STREAM | 创建unix stream socket
SWOOLE_SOCK_SYNC | 同步客户端

## SSL 加密方法

常量 | 作用
---|---
SWOOLE_SSLv3_METHOD | -
SWOOLE_SSLv3_SERVER_METHOD | -
SWOOLE_SSLv3_CLIENT_METHOD | -
SWOOLE_SSLv23_METHOD（默认加密方法） | -
SWOOLE_SSLv23_SERVER_METHOD | -
SWOOLE_SSLv23_CLIENT_METHOD | -
SWOOLE_TLSv1_METHOD | -
SWOOLE_TLSv1_SERVER_METHOD | -
SWOOLE_TLSv1_CLIENT_METHOD | -
SWOOLE_TLSv1_1_METHOD | -
SWOOLE_TLSv1_1_SERVER_METHOD | -
SWOOLE_TLSv1_1_CLIENT_METHOD | -
SWOOLE_TLSv1_2_METHOD | -
SWOOLE_TLSv1_2_SERVER_METHOD | -
SWOOLE_TLSv1_2_CLIENT_METHOD | -
SWOOLE_DTLSv1_METHOD | -
SWOOLE_DTLSv1_SERVER_METHOD | -
SWOOLE_DTLSv1_CLIENT_METHOD | -
SWOOLE_DTLS_SERVER_METHOD | -
SWOOLE_DTLS_CLIENT_METHOD | -

!> `SWOOLE_DTLSv1_METHOD`、`SWOOLE_DTLSv1_SERVER_METHOD`、`SWOOLE_DTLSv1_CLIENT_METHOD`已在 Swoole 版本 >= `v4.5.0` 中移除。

## SSL 协议

常量 | 作用
---|---
SWOOLE_SSL_TLSv1 | -
SWOOLE_SSL_TLSv1_1 | -
SWOOLE_SSL_TLSv1_2 | -
SWOOLE_SSL_TLSv1_3 | -
SWOOLE_SSL_SSLv2 | -
SWOOLE_SSL_SSLv3 | -

!> Swoole版本 >= `v4.5.4` 可用

## 日志等级

常量 | 作用
---|---
SWOOLE_LOG_DEBUG | 调试日志，仅作为内核开发调试使用
SWOOLE_LOG_TRACE | 跟踪日志，可用于跟踪系统问题，调试日志是经过精心设置的，会携带关键性信息
SWOOLE_LOG_INFO | 普通信息，仅作为信息展示
SWOOLE_LOG_NOTICE | 提示信息，系统可能存在某些行为，如重启、关闭
SWOOLE_LOG_WARNING | 警告信息，系统可能存在某些问题
SWOOLE_LOG_ERROR | 错误信息，系统发生了某些关键性的错误，需要即时解决
SWOOLE_LOG_NONE | 相当于关闭日志信息，日志信息不会抛出

!> `SWOOLE_LOG_DEBUG`和`SWOOLE_LOG_TRACE`两种日志，必须在编译Swoole扩展时使用[--enable-debug-log](/environment?id=debug参数)或[--enable-trace-log](/environment?id=debug参数)后才可以使用。正常版本中即使设置了`log_level = SWOOLE_LOG_TRACE`也是无法打印此类日志的。

## 跟踪标签

线上运行的服务，随时都有大量请求在处理，底层抛出的日志数量非常巨大。可使用`trace_flags`设置跟踪日志的标签，仅打印部分跟踪日志。`trace_flags`支持使用`|`或操作符设置多个跟踪项。

```php
$serv->set([
	'log_level' => SWOOLE_LOG_TRACE,
	'trace_flags' => SWOOLE_TRACE_SERVER | SWOOLE_TRACE_HTTP2,
]);
```

底层支持以下跟踪项，可使用`SWOOLE_TRACE_ALL`表示跟踪所有项目：

* `SWOOLE_TRACE_SERVER`
* `SWOOLE_TRACE_CLIENT`
* `SWOOLE_TRACE_BUFFER`
* `SWOOLE_TRACE_CONN`
* `SWOOLE_TRACE_EVENT`
* `SWOOLE_TRACE_WORKER`
* `SWOOLE_TRACE_REACTOR`
* `SWOOLE_TRACE_PHP`
* `SWOOLE_TRACE_HTTP2`
* `SWOOLE_TRACE_EOF_PROTOCOL`
* `SWOOLE_TRACE_LENGTH_PROTOCOL`
* `SWOOLE_TRACE_CLOSE`
* `SWOOLE_TRACE_HTTP_CLIENT`
* `SWOOLE_TRACE_COROUTINE`
* `SWOOLE_TRACE_REDIS_CLIENT`
* `SWOOLE_TRACE_MYSQL_CLIENT`
* `SWOOLE_TRACE_AIO`
* `SWOOLE_TRACE_ALL`
