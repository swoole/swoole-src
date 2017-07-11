--TEST--
swoole_http_client: post
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new swoole_http_client('127.0.0.1', 9501);
    $cli->set(array(
        'timeout' => 0.3,
    ));
    $cli->setHeaders(array('User-Agent' => "swoole"));
    $cli->on('close', function ($cli)
    {
        echo "close\n";
    });
    $cli->on('error', function ($cli)
    {
        echo "error\n";
    });
    $data = array('name' => "rango");
    $cli->post('/post', $data, function ($cli) use ($data)
    {
        assert($cli->statusCode == 200);
        $ret = json_decode($cli->body, true);
        assert($ret);
        assert(is_array($ret));
        assert(arrayEqual($ret, $data, false));
        $cli->close();
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    include __DIR__ . "/../include/api/http_server.php";
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
close
