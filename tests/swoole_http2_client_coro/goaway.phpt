--TEST--
swoole_http2_client_coro: http2 go away
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'nghttp2.org';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => 1,
        'ssl_host_name' => $domain
    ]);
    if (!$cli->connect()) {
        exit; // we can't connect to this website without proxy in China so we skip it.
    }
    $cli->goaway(SWOOLE_HTTP2_ERROR_NO_ERROR, '[GOAWAY] nothing~bye~bye~');
    assert(!$cli->recv(-1));
    assert(!$cli->connected);
});
?>
--EXPECT--
