<?php
$http = new swoole_http_server("127.0.0.1", 9501);

$http->on('request', function ($request, $response) {
	var_dump($request->header, $request->get, $request->post, $request->cookie, $request->info);
	$response->header("Location: http://www.baidu.com/");
	$response->write("<h1>Hello Swoole</h1>");
	$response->end(); //close connection
});

$http->on('message', function ($request, $response) {
	var_dump($request->message);
	$response->write("some data\n");
	
});

$http->start();
