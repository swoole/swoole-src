--TEST--
swoole_http_client_coro: http client with http_proxy
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_http_proxy();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $domain = 'mail.qq.com';
        $cli = new Swoole\Coroutine\Http\Client($domain, 443, true);
        $cli->setHeaders(['Host' => $domain]);
        $cli->set([
            'timeout'         => 30,
            'http_proxy_host' => HTTP_PROXY_HOST,
            'http_proxy_port' => HTTP_PROXY_PORT
        ]);
        $result = $cli->get('/');
        Assert::assert($result);
        Assert::assert(stripos($cli->body, 'tencent') !== false);
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $pm->wakeup();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
