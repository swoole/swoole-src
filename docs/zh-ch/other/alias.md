# 函数别名汇总

## 协程短名称

简化协程相关`API`的名称书写。可修改`php.ini`设置`swoole.use_shortname=On/Off`来开启/关闭短名，默认为开启。

所有的 `Swoole\Coroutine` 前缀的类名映射为`Co`。此外还有下面的一些映射：

### 创建协程

```php
//Swoole\Coroutine::create等价于go函数
go(function () {
	Co::sleep(0.5);
	echo 'hello';
});
go('test');
go([$object, 'method']);
```

### 通道操作

```php
//Coroutine\Channel可以简写为chan
$c = new chan(1);
$c->push($data);
$c->pop();
```

### 延迟执行

```php
//Swoole\Coroutine::defer可以直接用defer
defer(function () use ($db) {
    $db->close();
});
```

## 短名称方法

!> 以下这种方式中`go`和`defer`，Swoole 版本 >= `v4.6.3` 可用

```php
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\defer;

run(function () {
    defer(function () {
        echo "co1 end\n";
    });
    sleep(1);
    go(function () {
        usleep(100000);
        defer(function () {
            echo "co2 end\n";
        });
        echo "co2\n";
    });
    echo "co1\n";
});
```

## 协程System API

在`4.4.4`版本中系统操作相关的协程`API`从`Swoole\Coroutine`类中，迁移到了`Swoole\Coroutine\System`类中。独立为一个新模块。为了向下兼容，底层依然保留了在`Coroutine`类之上的别名方法。

* 例如 `Swoole\Coroutine::sleep`对应`Swoole\Coroutine\System::sleep`
* 例如 `Swoole\Coroutine::fgets`对应`Swoole\Coroutine\System::fgets`

## 类短别名映射关系

!> 推荐使用命名空间风格。

| 下划线类名风格                | 命名空间风格                  |
| --------------------------- | --------------------------- |
| swoole_server               | Swoole\Server               |
| swoole_client               | Swoole\Client               |
| swoole_process              | Swoole\Process              |
| swoole_timer                | Swoole\Timer                |
| swoole_table                | Swoole\Table                |
| swoole_lock                 | Swoole\Lock                 |
| swoole_atomic               | Swoole\Atomic               |
| swoole_atomic_long          | Swoole\Atomic\Long          |
| swoole_buffer               | Swoole\Buffer               |
| swoole_redis                | Swoole\Redis                |
| swoole_error                | Swoole\Error                |
| swoole_event                | Swoole\Event                |
| swoole_http_server          | Swoole\Http\Server          |
| swoole_http_client          | Swoole\Http\Client          |
| swoole_http_request         | Swoole\Http\Request         |
| swoole_http_response        | Swoole\Http\Response        |
| swoole_websocket_server     | Swoole\WebSocket\Server     |
| swoole_connection_iterator  | Swoole\Connection\Iterator  |
| swoole_exception            | Swoole\Exception            |
| swoole_http2_request        | Swoole\Http2\Request        |
| swoole_http2_response       | Swoole\Http2\Response       |
| swoole_process_pool         | Swoole\Process\Pool         |
| swoole_redis_server         | Swoole\Redis\Server         |
| swoole_runtime              | Swoole\Runtime              |
| swoole_server_port          | Swoole\Server\Port          |
| swoole_server_task          | Swoole\Server\Task          |
| swoole_table_row            | Swoole\Table\Row            |
| swoole_timer_iterator       | Swoole\Timer\Iterator       |
| swoole_websocket_closeframe | Swoole\Websocket\Closeframe |
| swoole_websocket_frame      | Swoole\Websocket\Frame      |
