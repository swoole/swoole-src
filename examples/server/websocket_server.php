<?php
$http = new swoole_http_server("127.0.0.1", 9501);
<<<<<<< Updated upstream
//$http->set(['worker_num' => 4, 'task_worker_num' => 4]);
=======
$http->set(['worker_num' => 4]);
>>>>>>> Stashed changes
$http->on('message', function($data, $response){
    //var_dump($data);
    $response->message("server send:".$data);
});
$http->on('request', function ($request, $response) {
	$response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});


$http->on('close', function(){
    echo "on close\n";
});


$http->start();
