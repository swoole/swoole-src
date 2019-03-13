--TEST--
swoole_http_client_coro: error handler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'httpbin.org';
    $cli = new Swoole\Coroutine\Http\Client($domain, 443, true);
    $cli->set([
        'timeout' => 10,
        'ssl_host_name' => $domain
    ]);
    $random = get_safe_random(16);
    assert($cli->get('/get?foo=' . $random));
    assert(strpos($cli->body, $random) !== false);
    echo "DONE\n";
});
swoole_event_wait();
?>
--EXPECT--
DONE
