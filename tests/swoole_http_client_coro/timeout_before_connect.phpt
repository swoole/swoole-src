--TEST--
swoole_http_client_coro: use timeout and timeout before connect
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('foreign network dns error');
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $host = 'www.qq.com';
    $requestHeaders = [
        'Host' => $host
    ];

    $cli1 = new Swoole\Coroutine\Http\Client($host, 80);
    $cli1->setHeaders($requestHeaders);
    $cli1->set(['timeout' => 0.001]);
    $cli1->setDefer(true);
    $cli1->get('/');
    assert($cli1->recv() === false);

    $cli2 = new Swoole\Coroutine\Http\Client($host, 80);
    $cli2->setHeaders($requestHeaders);
    $cli2->setDefer(true);

    $cli1->get('/');
    $cli2->get('/');

    $retval = $cli1->recv();
    assert($retval === false);
    assert($cli2->recv() === true);
    assert($cli1->statusCode === -2);
    if (!assert($cli2->statusCode === 200)) {
        var_dump($cli2);
    }
});
swoole_event::wait();
?>
--EXPECT--