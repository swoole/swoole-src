--TEST--
swoole_http_client: socks5 proxy
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_proxy();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) {
    $domain = 'www.facebook.com';
    $cli = new Swoole\Http\Client($domain, 80);
    $cli->setHeaders(['Host' => $domain]);
    $cli->set([
        'timeout' => 5,
        'socks5_host' => SOCKS5_PROXY_HOST,
        'socks5_port' => SOCKS5_PROXY_PORT
    ]);
    $cli->get('/', function ($cli) {
        assert($cli->statusCode == 302);
        assert($cli->headers['location'] == 'https://www.facebook.com/');
        $cli->close();
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $pm->wakeup();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
