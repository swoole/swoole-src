<?php
$http = new swoole_http_server("0.0.0.0", 9501);
//$http->setGlobal(HTTP_GLOBAL_ALL, HTTP_GLOBAL_GET|HTTP_GLOBAL_POST|HTTP_GLOBAL_COOKIE);
//$http->set(['worker_num' => 4, 'task_worker_num' => 4]);
$http->on('request', function ($request, $response) {
//	var_dump($request->cookie);
//var_dump($request);
//var_dump($_GET);
//var_dump($_POST);
//var_dump($_COOKIE);
//var_dump($_REQUEST);
	//$response->status(301);
    //$response->header("Location", "http://www.baidu.com/");
	//$response->cookie("hello", "world", time() + 3600);
    //$response->header("Content-Type", "text/html; charset=utf-8");
    //var_dump($request->rawContent());
    
    //var_dump($request->post);
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

$http->on('close', function(){
    echo "on close\n";
});


$http->start();
