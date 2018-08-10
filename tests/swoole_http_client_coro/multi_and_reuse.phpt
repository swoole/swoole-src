--TEST--
swoole_http_client_coro: reuse defer client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    function createDeferCli(string $host, bool $ssl = false): Swoole\Coroutine\Http\Client
    {
        $cli = new Swoole\Coroutine\Http\Client($host, $ssl ? 443 : 80, $ssl);
        $cli->set(['timeout' => 10]);
        $cli->setHeaders([
            'Host' => $host,
            'User-Agent' => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli->setDefer(true);

        return $cli;
    }

    $baidu = createDeferCli('www.baidu.com', true);
    $qq = createDeferCli('www.qq.com');

    //first
    $baidu->get('/');
    $qq->get('/');
    $baidu->recv(10);
    $qq->recv(10);
    assert($baidu->statusCode === 200);
    assert(stripos($baidu->body, 'baidu') !== false);
    assert($qq->statusCode === 200);
    assert(stripos($qq->body, 'tencent') !== false);

    //reuse
    $baidu->get('/duty/');
    $qq->get('/contract.shtml');
    $baidu->recv(10);
    $qq->recv(10);
    assert($baidu->statusCode === 200);
    assert(stripos($baidu->body, 'baidu') !== false);
    assert($qq->statusCode === 200);
    assert(stripos($qq->body, 'tencent') !== false);
});
?>
--EXPECT--