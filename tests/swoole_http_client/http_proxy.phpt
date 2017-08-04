--TEST--
swoole_http_client: get
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new swoole_http_client('127.0.0.1', 9501);
    $cli->setHeaders(['Host' => 'localhost']);
    $cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
    $cli->get('/get?json=true', function ($cli)
    {
        assert($cli->statusCode == 200);
        $ret = json_decode($cli->body, true);
        assert(is_array($ret) and $ret['json'] == 'true');
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
