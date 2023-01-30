<?php

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

$httpServer = new Swoole\Http\Server($host, $port, SWOOLE_PROCESS);
$httpServer->on("request", function ($request, $response) {
});

$httpServer->start();
