--TEST--
swoole_http_client: get
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_proxy();
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $domain = 'www.qq.com';
    $cli = new Swoole\Http\Client($domain, 80);
    $cli->setHeaders(['Host' => $domain]);
    $cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
    $cli->get('/', function ($cli) {
        assert($cli->statusCode == 200);
        assert(stripos($cli->body, 'tencent') !== false);
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
