<?php
use Swoole\Coroutine as co;

//const TEST = array('get', 'post', 'pipeline');
const TEST = array('pipeline');

co::create(function () use ($fp)
{
    $cli = new co\Http2\Client('127.0.0.1', 9518);

    $cli->set([ 'timeout' => 1]);
    var_dump($cli->connect());

    if (in_array('get', TEST))
    {
        $req = new co\Http2\Request;
        $req->path = "/index.html";
        $req->headers = [
            'host' => "localhost",
            "user-agent" => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
            'accept-encoding' => 'gzip',
        ];
        $req->cookies = ['name' => 'rango', 'email' => '1234@qq.com'];
        var_dump($cli->send($req));

        $resp = $cli->recv();
        var_dump($resp);
    }

    if (in_array('post', TEST))
    {
        $req2 = new co\Http2\Request;
        $req2->path = "/index.php";
        $req2->headers = [
            'host' => "localhost",
            "user-agent" => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
            'accept-encoding' => 'gzip',
        ];
        $req2->data = "hello world\n";
        var_dump($cli->send($req2));

        $resp = $cli->recv();
        var_dump($resp);
    }

    if (in_array('pipeline', TEST))
    {
        $req3 = new co\Http2\Request;
        $req3->path = "/index.php";
        $req3->headers = [
            'host' => "localhost",
            "user-agent" => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
            'accept-encoding' => 'gzip',
        ];
        $req3->pipeline = true;
        $req3->method = "POST";
        $streamId = $cli->send($req3);

        $cli->write($streamId, ['int' => rand(1000, 9999)]);
        $cli->write($streamId, ['int' => rand(1000, 9999)]);
        //end stream
        $cli->write($streamId, ['int' => rand(1000, 9999), 'end' => true], true);

        var_dump($cli->recv());
    }

//    $cli->close();
});