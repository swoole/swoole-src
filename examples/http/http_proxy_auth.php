<?php

$cli = new swoole_http_client('127.0.0.1', 80);
$cli->set(array(
    'http_proxy_host' => "127.0.0.1",
    'http_proxy_port' => 33080,
    'http_proxy_user' => 'test',
    'http_proxy_password' => 'test',
));
$cli->setHeaders([
    'Host' => "localhost",
    "User-Agent" => 'Chrome/49.0.2587.3',
]);
$cli->get('/', function ($cli) {
    echo "Length: " . strlen($cli->body) . ", statusCode=".$cli->statusCode."\n";
    $cli->close();     
    echo $cli->body;
});


