--TEST--
swoole_http_client_coro: disable keep alive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $host = 'www.qq.com';
    $cli = new Swoole\Coroutine\Http\Client($host, 443, true);
    $cli->set([
        'timeout' => 10,
        'keep_alive' => false
    ]);
    $cli->setHeaders(['Host' => $host]);
    $cli->get('/');
    Assert::eq($cli->statusCode, 200);

    Assert::true($cli->get('/contract.shtml'));
    Assert::eq($cli->statusCode, 200);

    // failed clear
    $cli->set([
        'timeout' => 0.001
    ]);
    Assert::false($cli->get('/contract.shtml'));
    Assert::assert(empty($cli->headers));
    Assert::assert(empty($cli->body));
});
?>
--EXPECT--