--TEST--
swoole_https_client: socks5 proxy
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
    $domain = 'www.google.com';
    $cli = new Swoole\Http\Client($domain, 443, true);
    $cli->setHeaders(['Host' => $domain]);
    $cli->set([
        'timeout' => 5,
        'socks5_host' => SOCKS5_PROXY_HOST,
        'socks5_port' => SOCKS5_PROXY_PORT
    ]);
    $cli->get('/', function ($cli) {
        assert($cli->statusCode == 200);
        assert(stripos($cli->body, 'google.com') !== false);
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
