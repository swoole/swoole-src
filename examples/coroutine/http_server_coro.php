<?php
go(function () {
	$server = new Co\Http\Server("127.0.0.1", 9501, $ssl);
	/**
	 * 静态文件处理器
	 */
	//$server->handle('/static', $server->getStaticHandler());
	/**
	 * WebSocket应用
	 */
	$server->handle('/websocket', function ($ctx) {
		$ctx->response->upgrade();
		while(true) {
			$frame = $ctx->recv();
			echo $frame->data;
			$ctx->push("hello world");
		}
	});
	/**
	 * Http应用
	 */
	$server->handle('/', function ($request, $response) {
		var_dump($request->get);
		$response->end("<h1>hello world</h1>");
	});

	$server->handle('/test', function ($request, $response) {
		var_dump($request->get);
		$response->end("<h1>Test</h1>");
	});

	$server->start();
});

swoole_event_wait();