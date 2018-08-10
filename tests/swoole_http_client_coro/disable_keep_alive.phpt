--TEST--
swoole_http_client_coro: disable keep alive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $host = 'www.qq.com';
    $cli = new \Swoole\Coroutine\Http\Client($host, 80);
    $cli->set([
        'timeout' => 10,
        'keep_alive' => false
    ]);
    $cli->setHeaders(['Host' => $host]);
    $cli->get('/');
    assert($cli->statusCode === 200);

    assert($cli->get('/contract.shtml') === true);
    assert($cli->statusCode === 200);

    // failed clear
    $cli->set([
        'timeout' => 0.001
    ]);
    assert($cli->get('/contract.shtml') === false);
    assert(empty($cli->headers));
    assert(empty($cli->body));
});
?>
--EXPECT--