--TEST--
swoole_http2_client_coro: send only without recv and use sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.zhihu.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => 5,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();
    $req = new Swoole\Http2\Request;
    $req->path = '/';
    $req->headers = [
        'host' => $domain,
        "user-agent" => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip'
    ];
    Assert::assert($cli->send($req));
    // not recv here (core dump before ver < 4.0.3)
    co::sleep(1);
});
?>
--EXPECT--
