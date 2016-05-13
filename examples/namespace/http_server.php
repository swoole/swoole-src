<?php
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$serv = new Server('127.0.0.1', 9501);

$serv->on('Request', function(Request $req, Response $resp) {
    var_dump($req->header, get_class($req));
    $resp->end("<h1>Hello Swoole</h1>");
});

$serv->start();

