--TEST--
swoole_coroutine: httpclient with http_proxy
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    co::create(function () {
        $cli = new co\http\client('127.0.0.1', 9501);
        $cli->setHeaders(['Host' => 'localhost']);
        $cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
        $result = $cli->get('/get?json=true');
        assert($result);
        $ret = json_decode($cli->body, true);
        assert(is_array($ret) and $ret['json'] == 'true');
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
