<?php
$http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
//$http->set(['worker_num' => 4, 'task_worker_num' => 4]);
$http->on('request', function ($request, $response) {
//	var_dump($request->cookie);
	//$response->status(301);
    //$response->header("Location", "http://www.baidu.com/");
	//$response->cookie("hello", "world", time() + 3600);
    //$response->header("Content-Type", "text/html; charset=utf-8");
    var_dump($request->rawContent());
    
    var_dump($request->post);
	$response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
    //global $http;
    //$http->task("hello world");
});

$http->on('finish', function(){
    echo "task finish";
});

$http->on('task', function(){
    echo "async task\n";
});

$http->start();
