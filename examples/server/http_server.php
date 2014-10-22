<?php
$http = new swoole_http_server("127.0.0.1", 9501);

$http->on('request', function ($request, $response) {
	var_dump($request->header);
	var_dump($request->get);
	var_dump($request->post);
	
	$response->header("Location: http://www.baidu.com/");
	$response->write("<h1>Hello Swoole</h1>");
	/**
	 * close connection
	 */
	$response->end();
});

$http->on('message', function ($request, $response) {
	var_dump($request->message);
	/**
	 * WebSocket->send
	 */
	$response->write("some data\n");
	
});

$http->start();