<?php

require_once __DIR__ . "/http_server.php";

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

(new HttpServer($host, $port, false))->start();