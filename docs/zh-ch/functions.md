# 函数列表

Swoole 除了网络通信相关的函数外，还提供了一些获取系统信息的函数供PHP程序使用。

## swoole_set_process_name()

用于设置进程的名称。修改进程名称后，通过ps命令看到的将不再是`php your_file.php`，而是设定的字符串。

此函数接受一个字符串参数。

此函数与PHP5.5提供的[cli_set_process_title](https://www.php.net/manual/zh/function.cli-set-process-title.php)功能是相同的。但`swoole_set_process_name`可用于PHP5.2之上的任意版本。`swoole_set_process_name`兼容性比`cli_set_process_title`要差，如果存在`cli_set_process_title`函数则优先使用`cli_set_process_title`。

```php
function swoole_set_process_name(string $name): void
```

使用示例：

```php
swoole_set_process_name("swoole server");
```

### 如何为Swoole Server重命名各个进程名称 <!-- {docsify-ignore} -->

* [onStart](/server/events?id=onstart)调用时修改主进程名称
* [onManagerStart](/server/events?id=onmanagerstart)调用时修改管理进程(`manager`)的名称
* [onWorkerStart](/server/events?id=onworkerstart)调用时修改worker进程名称
 
!> 低版本Linux内核和Mac OSX不支持进程重命名  

## swoole_strerror()

将错误码转换成错误信息。

函数原型：

```php
function swoole_strerror(int $errno, int $error_type = 1): string
```

错误类型:

* `1`：标准的`Unix Errno`，由系统调用错误产生，如`EAGAIN`、`ETIMEDOUT`等
* `2`：`getaddrinfo`错误码，由`DNS`操作产生
* `9`：`Swoole`底层错误码，使用`swoole_last_error()`得到

使用示例：

```php
var_dump(swoole_strerror(swoole_last_error(), 9));
```

## swoole_version()

获取swoole扩展的版本号，如`1.6.10`

```php
function swoole_version(): string
```

使用示例：

```php
var_dump(SWOOLE_VERSION); //全局变量SWOOLE_VERSION同样表示swoole扩展版本
var_dump(swoole_version());
/**
返回值：
string(6) "1.9.23"
string(6) "1.9.23"
**/
```

## swoole_errno()

获取最近一次系统调用的错误码，等同于`C/C++`的`errno`变量。

```php
function swoole_errno(): int
```

错误码的值与操作系统有关。可使用`swoole_strerror`将错误转换为错误信息。

## swoole_get_local_ip()

此函数用于获取本机所有网络接口的IP地址。

```php
function swoole_get_local_ip(): array
```

使用示例：

```php
// 获取本机所有网络接口的IP地址
$list = swoole_get_local_ip();
print_r($list);
/**
返回值
Array
(
      [eno1] => 10.10.28.228
      [br-1e72ecd47449] => 172.20.0.1
      [docker0] => 172.17.0.1
)
**/
```

!>注意
* 目前只返回IPv4地址，返回结果会过滤掉本地loop地址127.0.0.1。
* 结果数组是以interface名称为key的关联数组。比如 `array("eth0" => "192.168.1.100")`
* 此函数会实时调用`ioctl`系统调用获取接口信息，底层无缓存

## swoole_clear_dns_cache()

清除swoole内置的DNS缓存，对`swoole_client`和`swoole_async_dns_lookup`有效。

```php
function swoole_clear_dns_cache()
```

## swoole_get_local_mac()

获取本机网卡`Mac`地址。

```php
function swoole_get_local_mac(): array
```

* 调用成功返回所有网卡的`Mac`地址

```php
array(4) {
  ["lo"]=>
  string(17) "00:00:00:00:00:00"
  ["eno1"]=>
  string(17) "64:00:6A:65:51:32"
  ["docker0"]=>
  string(17) "02:42:21:9B:12:05"
  ["vboxnet0"]=>
  string(17) "0A:00:27:00:00:00"
}
```

## swoole_cpu_num()

获取本机CPU核数。

```php
function swoole_cpu_num(): int
```

* 调用成功返回CPU核数，例如：

```shell
php -r "echo swoole_cpu_num();"
```

## swoole_last_error()

获取最近一次Swoole底层的错误码。

```php
function swoole_last_error(): int
```

可使用`swoole_strerror(swoole_last_error(), 9)`将错误转换为错误信息, 完整错误信息列表看 [Swoole错误码列表](/other/errno?id=swoole)

## swoole_mime_type_add()

添加新的mime类型到内置的mime类型表上。

```php
function swoole_mime_type_add(string $suffix, string $mime_type): bool
```

## swoole_mime_type_set()

修改某个mime类型, 失败(如不存在)返回`false`。

```php
function swoole_mime_type_set(string $suffix, string $mime_type): bool
```

## swoole_mime_type_delete()

删除某个mime类型, 失败(如不存在)返回`false`。

```php
function swoole_mime_type_delete(string $suffix): bool
```

## swoole_mime_type_get()

获取文件名对应的mime类型。

```php
function swoole_mime_type_get(string $filename): string
```

## swoole_mime_type_exists()

获取后缀对应的mime类型是否存在。

```php
function swoole_mime_type_exists(string $suffix): bool
```

## swoole_substr_json_decode()

零拷贝 JSON 反序列化，除去`$offset`和`$length`以外，其他参数和 [json_decode](https://www.php.net/manual/en/function.json-decode.php) 一致。

!> Swoole 版本 >= `v4.5.6` 可用，从`v4.5.7`版本开始需要在编译时增加[--enable-swoole-json](/environment?id=通用参数)参数启用。使用场景参考[Swoole 4.5.6 支持零拷贝 JSON 或 PHP 反序列化](https://wenda.swoole.com/detail/107587)

```php
function swoole_substr_json_decode(string $packet, int $offset, int $length, bool $assoc = false, int $depth = 512, int $options = 0)
```

  * **示例**

```php
$val = json_encode(['hello' => 'swoole']);
$str = pack('N', strlen($val)) . $val . "\r\n";
$l = strlen($str) - 6;
var_dump(json_decode(substr($str, 4, $l), true));
var_dump(swoole_substr_json_decode($str, 4, $l, true));
```

## swoole_substr_unserialize()

零拷贝 PHP 反序列化，除去`$offset`和`$length`以外，其他参数和 [unserialize](https://www.php.net/manual/en/function.unserialize.php) 一致。

!> Swoole 版本 >= `v4.5.6` 可用。使用场景参考[Swoole 4.5.6 支持零拷贝 JSON 或 PHP 反序列化](https://wenda.swoole.com/detail/107587)

```php
function swoole_substr_unserialize(string $packet, int $offset, int $length, array $options= [])
```

  * **示例**

```php
$val = serialize('hello');
$str = pack('N', strlen($val)) . $val . "\r\n";
$l = strlen($str) - 6;
var_dump(unserialize(substr($str, 4, $l)));
var_dump(swoole_substr_unserialize($str, 4, $l));
```

## swoole_error_log()

输出错误信息到日志中。`$level`为[日志等级](/consts?id=日志等级)。

!> Swoole 版本 >= `v4.5.8` 可用

```php
function swoole_error_log(int $level, string $msg)
```

## swoole_clear_error()

清除 socket 的错误或者最后的错误代码上的错误。

!> Swoole 版本 >= `v4.6.0` 可用

```php
function swoole_clear_error()
```

## swoole_coroutine_socketpair()

协程版本的 [socket_create_pair](https://www.php.net/manual/en/function.socket-create-pair.php) 。

!> Swoole 版本 >= `v4.6.0` 可用

```php
function swoole_coroutine_socketpair(int $domain , int $type , int $protocol): array|bool
```

## swoole_async_set

此函数可以设置异步`IO`相关的选项。

```php
function swoole_async_set(array $settings)
```

- enable_signalfd 开启和关闭`signalfd`特性的使用
- enable_coroutine 开关内置协程，[详见](/server/setting?id=enable_coroutine)
- aio_core_worker_num 设置 AIO 最小进程数
- aio_worker_num 设置 AIO 最大进程数

## swoole_error_log_ex()

写入指定等级和错误码的日志。

```php
function swoole_error_log_ex(int $level, int $error, string $msg)
```

!> Swoole 版本 >= `v4.8.1` 可用

## swoole_ignore_error()

忽略指定的错误码的错误日志。

```php
function swoole_ignore_error(int $error)
```

!> Swoole 版本 >= `v4.8.1` 可用
