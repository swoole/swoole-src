# 协程Redis客户端

!> 本客户端不再推荐使用，推荐使用`Swoole\Runtime::enableCoroutine + phpredis` 或 `predis` 的方式，即[一键协程化](/runtime)原生`PHP`的`redis`客户端使用。

## 使用示例

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $val = $redis->get('key');
});
```

!> `subscribe` `pSubscribe`无法用于`defer(true)`的情况。

## 方法

!> 方法的使用基本与 [phpredis](https://github.com/phpredis/phpredis) 保持一致。

以下说明不同于[phpredis](https://github.com/phpredis/phpredis)的实现：

1、尚未实现的Redis命令：`scan object sort migrate hscan sscan zscan`；

2、`subscribe pSubscribe`的使用方式，无需设置回调函数；

3、序列化PHP变量的支持，在`connect()`方法的第三个参数设置为`true`时，开启序列化`PHP`变量特性，默认为`false`

### __construct()

Redis协程客户端构造方法，可以设置`Redis`连接的配置选项，和`setOptions()`方法参数一致。

```php
Swoole\Coroutine\Redis::__construct(array $options = null);
```

### setOptions()

4.2.10版本后新增了该方法, 用于在构造和连接后设置`Redis`客户端的一些配置

该函数是Swoole风格的, 需通过`Key-Value`键值对数组来配置

```php
Swoole\Coroutine\Redis->setOptions(array $options): void
```

  * **可配置选项**

key | 说明
---|---
`connect_timeout` | 连接的超时时间, 默认为全局的协程`socket_connect_timeout`(1秒)
`timeout` | 超时时间, 默认为全局的协程`socket_timeout`，参考[客户端超时规则](/coroutine_client/init?id=超时规则)
`serialize` | 自动序列化, 默认关闭
`reconnect` | 自动连接尝试次数, 如果连接由于超时等原因被`close`正常断开, 下一次发起请求时, 会自动尝试连接然后再发送请求, 默认为`1`次(`true`), 一旦失败指定次数后不会再继续尝试, 需手动重连. 该机制仅用于连接保活, 不会重发请求导致不幂等接口出错等问题
`compatibility_mode` | `hmGet/hGetAll/zRange/zRevRange/zRangeByScore/zRevRangeByScore` 函数返回结果与`php-redis`不一致的兼容解决方案，开启之后 `Co\Redis` 和 `php-redis` 返回结果一致，默认关闭 【此配置项在`v4.4.0`或更高版本可用】

### set()

存数据。

```php
Swoole\Coroutine\Redis->set(string $key, mixed $value, array|int $option): bool
```

  * **参数** 

    * **`string $key`**
      * **功能**：数据的key
      * **默认值**：无
      * **其它值**：无

    * **`string $value`**
      * **功能**：数据内容【非字符串类型会自动序列化】
      * **默认值**：无
      * **其它值**：无

    * **`string $options`**
      * **功能**：选项
      * **默认值**：无
      * **其它值**：无

      !> `$option` 说明：  
      `整型`：设置过期时间，如`3600`  
      `数组`：高级过期设置，如`['nx', 'ex' => 10]` 、`['xx', 'px' => 1000]`

      !> `px`: 表示毫秒级过期时间  
      `ex`: 表示秒级过期时间  
      `nx`: 表示不存在时设置超时  
      `xx`: 表示存在时设置超时

### request()

向Redis服务器发送一个自定义的指令。类似于phpredis的rawCommand。

```php
Swoole\Coroutine\Redis->request(array $args): void
```

  * **参数** 

    * **`array $args`**
      * **功能**：参数列表，必须为数组格式参数。【第一个元素必须为`Redis`指令，其他的元素是指令的参数，底层会自动打包为`Redis`协议请求进行发送。】
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

取决于`Redis`服务器对指令的处理方式，可能会返回数字、布尔型、字符串、数组等类型。

  * **使用示例** 

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379); // 若是本地UNIXSocket则host参数应以形如`unix://tmp/your_file.sock`的格式填写
    $res = $redis->request(['object', 'encoding', 'key1']);
    var_dump($res);
});
```

## 属性

### errCode

错误代码。

错误代码 | 说明
---|---
1 | Error in read or write
2 | Everything else...
3 | End of file
4 | Protocol error
5 | Out of memory

### errMsg

错误消息。

### connected

判断当前`Redis`客户端是否连接到了服务器。

## 常量

用于`multi($mode)`方法，默认为`SWOOLE_REDIS_MODE_MULTI`模式：

* SWOOLE_REDIS_MODE_MULTI
* SWOOLE_REDIS_MODE_PIPELINE

用于判断`type()`命令的返回值：

* SWOOLE_REDIS_TYPE_NOT_FOUND
* SWOOLE_REDIS_TYPE_STRING
* SWOOLE_REDIS_TYPE_SET
* SWOOLE_REDIS_TYPE_LIST
* SWOOLE_REDIS_TYPE_ZSET
* SWOOLE_REDIS_TYPE_HASH

## 事务模式

可使用`multi`和`exec`实现`Redis`的事务模式。

  * **提示**

    * 使用`mutli`指令启动事务，之后所有指令将被加入到队列中等待执行
    * 使用`exec`指令执行事务中的所有操作，并一次性返回所有结果

  * **使用示例**

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $redis->multi();
    $redis->set('key3', 'rango');
    $redis->get('key1');
    $redis->get('key2');
    $redis->get('key3');

    $result = $redis->exec();
    var_dump($result);
});
```

## 订阅模式

!> Swoole版本 >= v4.2.13 可用，**4.2.12及以下版本订阅模式存在BUG**

### 订阅

与`phpredis`不同，`subscribe/psubscribe`为协程风格。

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    if ($redis->subscribe(['channel1', 'channel2', 'channel3'])) // 或者使用psubscribe
    {
        while ($msg = $redis->recv()) {
            // msg是一个数组, 包含以下信息
            // $type # 返回值的类型：显示订阅成功
            // $name # 订阅的频道名字 或 来源频道名字
            // $info  # 目前已订阅的频道数量 或 信息内容
            list($type, $name, $info) = $msg;
            if ($type == 'subscribe') { // 或psubscribe
                // 频道订阅成功消息，订阅几个频道就有几条
            } else if ($type == 'unsubscribe' && $info == 0){ // 或punsubscribe
                break; // 收到取消订阅消息，并且剩余订阅的频道数为0，不再接收，结束循环
            } else if ($type == 'message') {  // 若为psubscribe，此处为pmessage
                var_dump($name); // 打印来源频道名字
                var_dump($info); // 打印消息
                // balabalaba.... // 处理消息
                if ($need_unsubscribe) { // 某个情况下需要退订
                    $redis->unsubscribe(); // 继续recv等待退订完成
                }
            }
        }
    }
});
```

### 退订

退订使用`unsubscribe/punsubscribe`，`$redis->unsubscribe(['channel1'])`

此时`$redis->recv()`将会接收到一条取消订阅消息，若取消订阅多个频道，则会收到多条。
    
!> 注意：退订后务必继续`recv()`到收到最后一条取消订阅消息（`$msg[2] == 0`），收到此条消息后，才会退出订阅模式

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    if ($redis->subscribe(['channel1', 'channel2', 'channel3'])) // or use psubscribe
    {
        while ($msg = $redis->recv()) {
            // msg is an array containing the following information
            // $type # return type: show subscription success
            // $name # subscribed channel name or source channel name
            // $info  # the number of channels or information content currently subscribed
            list($type, $name, $info) = $msg;
            if ($type == 'subscribe') // or psubscribe
            {
                // channel subscription success message
            }
            else if ($type == 'unsubscribe' && $info == 0) // or punsubscribe
            {
                break; // received the unsubscribe message, and the number of channels remaining for the subscription is 0, no longer received, break the loop
            }
            else if ($type == 'message') // if it's psubscribe，here is pmessage
            {
                // print source channel name
                var_dump($name);
                // print message
                var_dump($info);
                // handle messsage
                if ($need_unsubscribe) // in some cases, you need to unsubscribe
                {
                    $redis->unsubscribe(); // continue recv to wait unsubscribe finished
                }
            }
        }
    }
});
```

## 兼容模式

`Co\Redis` 的 `hmGet/hGetAll/zrange/zrevrange/zrangebyscore/zrevrangebyscore`指令返回结果与`phpredis`扩展返回值格式不一致的问题，已经得到解决 [#2529](https://github.com/swoole/swoole-src/pull/2529)。

为了兼容老版本，在加上 `$redis->setOptions(['compatibility_mode' => true]);` 配置后，即可保证 `Co\Redis` 和 `phpredis` 返回结果一致。

!> Swoole版本 >= `v4.4.0` 可用

```php
use Swoole\Coroutine\Redis;
use function Swoole\Coroutine\run;

run(function () {
    $redis = new Redis();
    $redis->setOptions(['compatibility_mode' => true]);
    $redis->connect('127.0.0.1', 6379);

    $co_get_val = $redis->get('novalue');
    $co_zrank_val = $redis->zRank('novalue', 1);
    $co_hgetall_val = $redis->hGetAll('hkey');
    $co_hmget_val = $redis->hmGet('hkey', array(3, 5));
    $co_zrange_val = $redis->zRange('zkey', 0, 99, true);
    $co_zrevrange_val = $redis->zRevRange('zkey', 0, 99, true);
    $co_zrangebyscore_val = $redis->zRangeByScore('zkey', 0, 99, ['withscores' => true]);
    $co_zrevrangebyscore_val = $redis->zRevRangeByScore('zkey', 99, 0, ['withscores' => true]);
});
```