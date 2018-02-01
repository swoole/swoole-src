<?php
use Swoole\Coroutine as co;

co::create(function () use ($fp)
{
    $cli = new co\Http2\Client('127.0.0.1', 9518);

    $cli->set([ 'timeout' => 1]);
    var_dump($cli->connect());

    $req = new co\Http2\Request;
    $req->path = "/index.html";
    $req->headers = [
        'host' => "localhost",
        "user-agent" => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip',
    ];
    var_dump($cli->send($req));

    $req2 = new co\Http2\Request;
    $req2->path = "/index.php";
    $req2->headers = [
        'host' => "localhost",
        "user-agent" => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip',
    ];
    var_dump($cli->send($req2));

    $resp = $cli->recv();
    var_dump($resp);
    $resp = $cli->recv();
    var_dump($resp);

    $cli->close();
});