<?php
$http = new swoole_http_server("127.0.0.1", 9501);
$http->set(['worker_num' => 4]);
$http->on('request', function ($channel, $request) {
	//var_dump($request, $channel);
    //$channel->header("Location: http://www.baidu.com/");
    $channel->response("<h1>Hello Swoole</h1>");
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
