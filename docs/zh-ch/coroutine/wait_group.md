# Coroutine\WaitGroup

在`Swoole4`中可以使用[Channel](/coroutine/channel)实现协程间的通信、依赖管理、协程同步。基于[Channel](/coroutine/channel)可以很容易地实现`Golang`的`sync.WaitGroup`功能。

## 实现代码

> 此功能是使用PHP编写的功能，并不是C/C++代码，实现源代码在 [Library](https://github.com/swoole/library/blob/master/src/core/Coroutine/WaitGroup.php) 当中

* `add`方法增加计数
* `done`表示任务已完成
* `wait`等待所有任务完成恢复当前协程的执行
* `WaitGroup`对象可以复用，`add`、`done`、`wait`之后可以再次使用

## 使用示例

```php
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\WaitGroup;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $wg = new WaitGroup();
    $result = [];

    $wg->add();
    //启动第一个协程
    Coroutine::create(function () use ($wg, &$result) {
        //启动一个协程客户端client，请求淘宝首页
        $cli = new Client('www.taobao.com', 443, true);
        $cli->setHeaders([
            'Host' => 'www.taobao.com',
            'User-Agent' => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli->set(['timeout' => 1]);
        $cli->get('/index.php');

        $result['taobao'] = $cli->body;
        $cli->close();

        $wg->done();
    });

    $wg->add();
    //启动第二个协程
    Coroutine::create(function () use ($wg, &$result) {
        //启动一个协程客户端client，请求百度首页
        $cli = new Client('www.baidu.com', 443, true);
        $cli->setHeaders([
            'Host' => 'www.baidu.com',
            'User-Agent' => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli->set(['timeout' => 1]);
        $cli->get('/index.php');

        $result['baidu'] = $cli->body;
        $cli->close();

        $wg->done();
    });

    //挂起当前协程，等待所有任务完成后恢复
    $wg->wait();
    //这里 $result 包含了 2 个任务执行结果
    var_dump($result);
});
```