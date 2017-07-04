<?php

function create()
{
    $cli = new swoole_http_client("127.0.0.1", 80);
    $cli->setHeaders([
        "Host" => "xxx.xxx.xxx",
    ]);
    $cli->on("error", function() { echo "error"; });
    $cli->on("close", function() { echo "close\n\n"; post(create()); });
    return $cli;
}
post(create());
function post($cli) {
    $cli->post("/xxx/xxx/xxx", [
        "ua" => "younipf",
        "debug" => "json",
    ], function($cli) {
        echo $cli->statusCode, "\n";
        post($cli);
    });
}


$payload = <<<HTML
HTTP/1.1 400 Bad Request\r\nDate: Fri, 10 Mar 2017 10:47:07 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 242\r\nConnection: close\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<h1>400 Bad Request</h1>\r\n<p>Your browser sent a request that this swoole_server could not understand.</body>\r\n</html>\r\n
HTML;
