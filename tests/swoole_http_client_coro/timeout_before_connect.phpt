--TEST--
swoole_http_client_coro: use timeout and timeout before connect
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('foreign network dns error');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $host = 'www.qq.com';
    $requestHeaders = [
        'Host' => $host
    ];

    $cli1 = new Swoole\Coroutine\Http\Client($host, 443, true);
    $cli1->setHeaders($requestHeaders);
    $cli1->set(['timeout' => 0.001]);
    $cli1->setDefer(true);
    $cli1->get('/');
    assert($cli1->recv() === false);
    assert($cli1->errCode === SOCKET_ETIMEDOUT);
    assert($cli1->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);

    $cli2 = new Swoole\Coroutine\Http\Client($host, 443, true);
    $cli2->setHeaders($requestHeaders);
    $cli2->setDefer(true);

    $cli2->get('/');
    $cli1->get('/');
    assert($cli1->recv() === false);
    assert($cli1->errCode === SOCKET_ETIMEDOUT);
    assert($cli1->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
    assert($cli2->recv() === true);
    assert($cli2->statusCode === 200 && strpos($cli2->body, 'tencent') !== false);
});
swoole_event::wait();
?>
--EXPECT--