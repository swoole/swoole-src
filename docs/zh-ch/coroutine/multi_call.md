# 并发调用

[//]: # (
此处删除了setDefer特性，因为支持setDefer的客户端都推荐用一键协程化了。
)

使用`子协程(go)`+`通道(channel)`实现并发请求。

!>建议先看[概览](/coroutine)，了解协程基本概念再看此节。

### 实现原理

* 在`onRequest`中需要并发两个`HTTP`请求，可使用`go`函数创建`2`个子协程，并发地请求多个`URL`
* 并创建了一个`chan`，使用`use`闭包引用语法，传递给子协程
* 主协程循环调用`chan->pop`，等待子协程完成任务，`yield`进入挂起状态
* 并发的两个子协程其中某个完成请求时，调用`chan->push`将数据推送给主协程
* 子协程完成`URL`请求后退出，主协程从挂起状态中恢复，继续向下执行调用`$resp->end`发送响应结果

### 使用示例

```php
$serv = new Swoole\Http\Server("127.0.0.1", 9503, SWOOLE_BASE);

$serv->on('request', function ($req, $resp) {
	$chan = new chan(2);
	go(function () use ($chan) {
		$cli = new Swoole\Coroutine\Http\Client('www.qq.com', 80);
			$cli->set(['timeout' => 10]);
			$cli->setHeaders([
			'Host' => "www.qq.com",
			"User-Agent" => 'Chrome/49.0.2587.3',
			'Accept' => 'text/html,application/xhtml+xml,application/xml',
			'Accept-Encoding' => 'gzip',
		]);
		$ret = $cli->get('/');
		$chan->push(['www.qq.com' => $cli->body]);
	});

	go(function () use ($chan) {
		$cli = new Swoole\Coroutine\Http\Client('www.163.com', 80);
		$cli->set(['timeout' => 10]);
		$cli->setHeaders([
			'Host' => "www.163.com",
			"User-Agent" => 'Chrome/49.0.2587.3',
			'Accept' => 'text/html,application/xhtml+xml,application/xml',
			'Accept-Encoding' => 'gzip',
		]);
		$ret = $cli->get('/');
		$chan->push(['www.163.com' => $cli->body]);
	});
	
	$result = [];
	for ($i = 0; $i < 2; $i++)
	{
		$result += $chan->pop();
	}
	$resp->end(json_encode($result));
});
$serv->start();
```

!> 使用`Swoole`提供的[WaitGroup](/coroutine/wait_group)功能，将更简单一些。