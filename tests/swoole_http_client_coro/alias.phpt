--TEST--
swoole_http_client_coro: alias
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.baidu.com';
    $cli = new Swoole\Coroutine\Http\Client($domain, 443, true);
    $cli->set([
        'timeout' => 10,
        'ssl_host_name' => $domain
    ]);
    $random = get_safe_random(16);
    Assert::assert($cli->get('/'));
    Assert::contains($cli->getBody(), 'baidu.com');
    Assert::same($cli->getStatusCode(), 200);
    Assert::assert(count($cli->getHeaders()) > 5);
    Assert::assert(count($cli->getCookies()) > 2);
    echo "DONE\n";
});
swoole_event_wait();
?>
--EXPECT--
DONE
