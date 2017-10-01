<?php
$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

$swoole = new swoole_server($host, $port);

$swoole->on("connect", function ($server, $fd) {
});

$swoole->on("receive", function ($server, $fd, $from_id, $data) {
});

$swoole->start();