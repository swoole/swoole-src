<?php
$http = new swoole_http_server("127.0.0.1", 9501);
$http->set(['worker_num' => 1]);
$http->on('request', function ($channel, $request) {
	var_dump($request->cookie);
	//$channel->status(301);
    //$channel->header("Location", "http://www.baidu.com/");
	//$channel->cookie("hello", "world", time() + 3600);
    //$channel->header("Content-Type", "text/html; charset=utf-8");
    $channel->response("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
    //$channel->end(); //close connection
});
//$http->on('message', function ($request, $response) {
//	var_dump($request->message);
//	/**
//	 * WebSocket->send
//	 */
//	$response->write("some data\n");
//
//});
$http->start();
