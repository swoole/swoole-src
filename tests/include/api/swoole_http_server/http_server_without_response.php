<?php

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

$httpServer = new swoole_http_server($host, $port);
$httpServer->on("request", function ($request, $response) {
});

$httpServer->start();