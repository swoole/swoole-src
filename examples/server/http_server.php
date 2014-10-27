<?php
$http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
$http->set(['worker_num' => 1]);
$http->on('request', function ($request, $response) {
//	var_dump($request->cookie);
	//$response->status(301);
    //$response->header("Location", "http://www.baidu.com/");
	//$response->cookie("hello", "world", time() + 3600);
    //$response->header("Content-Type", "text/html; charset=utf-8");
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});
$http->start();
