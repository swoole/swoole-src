# Redis\Server

一个兼容`Redis`服务器端协议的`Server`类，可基于此类实现`Redis`协议的服务器程序。

?> `Swoole\Redis\Server`继承自[Server](/server/tcp_init)，所以`Server`提供的所有`API`和配置项都可以使用，进程模型也是一致的。请参考[Server](/server/init)章节。

* **可用的客户端**

  * 任意编程语言的`redis`客户端，包括PHP的`redis`扩展和`phpredis`库
  * [Swoole\Coroutine\Redis](/coroutine_client/redis) 协程客户端
  * `Redis`提供的命令行工具，包括`redis-cli`、`redis-benchmark`

## 方法

`Swoole\Redis\Server`继承自`Swoole\Server`，可以使用父类提供的所有方法。

### setHandler

?> **设置`Redis`命令字的处理器。**

!> `Redis\Server`不需要设置[onReceive](/server/events?id=onreceive)回调。只需使用`setHandler`方法设置对应命令的处理函数，收到未支持的命令后会自动向客户端发送`ERROR`响应，消息为`ERR unknown command '$command'`。

```php
Swoole\Redis\Server->setHandler(string $command, callable $callback);
```

* **参数** 

  * **`string $command`**
    * **功能**：命令的名称
    * **默认值**：无
    * **其它值**：无

  * **`callable $callback`**
    * **功能**：命令的处理函数【回调函数返回字符串类型时会自动发送给客户端】
    * **默认值**：无
    * **其它值**：无

    !> 返回的数据必须为`Redis`格式，可使用`format`静态方法进行打包

### format

?> **格式化命令响应数据。**

```php
Swoole\Redis\Server::format(int $type, mixed $value = null);
```

* **参数** 

  * **`int $type`**
    * **功能**：数据类型，对应常量参考下文 [格式参数常量](/redis_server?id=格式参数常量)。
    * **默认值**：无
    * **其它值**：无
    
    !> 当`$type`为`NIL`类型时，不需要传入`$value`；`ERROR`和`STATUS`类型`$value`可选；`INT`、`STRING`、`SET`、`MAP`必填。

  * **`mixed $value`**
    * **功能**：值
    * **默认值**：无
    * **其它值**：无

### send

?> **使用[Swoole\Server](/server/methods?id=send)中的`send()`方法将数据发送给客户端。**

```php
Swoole\Server->send(int $fd, string $data): bool
```

## 常量

### 格式参数常量

主要用于`format`函数打包`Redis`响应数据

常量 | 说明
---|---
Server::NIL | 返回nil数据
Server::ERROR | 返回错误码
Server::STATUS | 返回状态
Server::INT | 返回整数，format必须传入参数值，类型必须为整数
Server::STRING | 返回字符串，format必须传入参数值，类型必须为字符串
Server::SET | 返回列表，format必须传入参数值，类型必须为数组
Server::MAP | 返回Map，format必须传入参数值，类型必须为关联索引数组

## 使用示例

### 服务端

```php
use Swoole\Redis\Server;

define('DB_FILE', __DIR__ . '/db');

$server = new Server("127.0.0.1", 9501, SWOOLE_BASE);

if (is_file(DB_FILE)) {
    $server->data = unserialize(file_get_contents(DB_FILE));
} else {
    $server->data = array();
}

$server->setHandler('GET', function ($fd, $data) use ($server) {
    if (count($data) == 0) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'GET' command"));
    }

    $key = $data[0];
    if (empty($server->data[$key])) {
        return $server->send($fd, Server::format(Server::NIL));
    } else {
        return $server->send($fd, Server::format(Server::STRING, $server->data[$key]));
    }
});

$server->setHandler('SET', function ($fd, $data) use ($server) {
    if (count($data) < 2) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'SET' command"));
    }

    $key = $data[0];
    $server->data[$key] = $data[1];
    return $server->send($fd, Server::format(Server::STATUS, "OK"));
});

$server->setHandler('sAdd', function ($fd, $data) use ($server) {
    if (count($data) < 2) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'sAdd' command"));
    }

    $key = $data[0];
    if (!isset($server->data[$key])) {
        $array[$key] = array();
    }

    $count = 0;
    for ($i = 1; $i < count($data); $i++) {
        $value = $data[$i];
        if (!isset($server->data[$key][$value])) {
            $server->data[$key][$value] = 1;
            $count++;
        }
    }

    return $server->send($fd, Server::format(Server::INT, $count));
});

$server->setHandler('sMembers', function ($fd, $data) use ($server) {
    if (count($data) < 1) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'sMembers' command"));
    }
    $key = $data[0];
    if (!isset($server->data[$key])) {
        return $server->send($fd, Server::format(Server::NIL));
    }
    return $server->send($fd, Server::format(Server::SET, array_keys($server->data[$key])));
});

$server->setHandler('hSet', function ($fd, $data) use ($server) {
    if (count($data) < 3) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'hSet' command"));
    }

    $key = $data[0];
    if (!isset($server->data[$key])) {
        $array[$key] = array();
    }
    $field = $data[1];
    $value = $data[2];
    $count = !isset($server->data[$key][$field]) ? 1 : 0;
    $server->data[$key][$field] = $value;
    return $server->send($fd, Server::format(Server::INT, $count));
});

$server->setHandler('hGetAll', function ($fd, $data) use ($server) {
    if (count($data) < 1) {
        return $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'hGetAll' command"));
    }
    $key = $data[0];
    if (!isset($server->data[$key])) {
        return $server->send($fd, Server::format(Server::NIL));
    }
    return $server->send($fd, Server::format(Server::MAP, $server->data[$key]));
});

$server->on('WorkerStart', function ($server) {
    $server->tick(10000, function () use ($server) {
        file_put_contents(DB_FILE, serialize($server->data));
    });
});

$server->start();
```

### 客户端

```shell
$ redis-cli -h 127.0.0.1 -p 9501
127.0.0.1:9501> set name swoole
OK
127.0.0.1:9501> get name
"swoole"
127.0.0.1:9501> sadd swooler rango
(integer) 1
127.0.0.1:9501> sadd swooler twosee guoxinhua
(integer) 2
127.0.0.1:9501> smembers swooler
1) "rango"
2) "twosee"
3) "guoxinhua"
127.0.0.1:9501> hset website swoole "www.swoole.com"
(integer) 1
127.0.0.1:9501> hset website swoole "swoole.com"
(integer) 0
127.0.0.1:9501> hgetall website
1) "swoole"
2) "swoole.com"
127.0.0.1:9501> test
(error) ERR unknown command 'test'
127.0.0.1:9501>
```
