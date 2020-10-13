--TEST--
swoole_http_client_coro: multi http client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli1 = new Swoole\Coroutine\Http\Client('www.baidu.com', 443, true);
    $cli1->set(['timeout' => 10]);
    $cli1->setHeaders([
        'Host' => 'www.baidu.com',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $cli1->setDefer(1);

    $cli2 = new Swoole\Coroutine\Http\Client('www.qq.com', 443, true);
    $cli2->set(['timeout' => 10]);
    $cli2->setHeaders([
        'Host' => 'www.qq.com',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $cli2->setDefer(1);

    $ret1 = ($cli1->get('/'));
    $ret2 = ($cli2->get('/'));
    if (!$ret1 or !$ret2)    {
        echo "ERROR\n";
        var_dump($cli1->errCode, $cli1->errMsg);
        var_dump($cli2->errCode, $cli2->errMsg);
    }
    else
    {
        Assert::assert($cli1->recv());
        Assert::assert($cli2->recv());
        Assert::contains($cli1->body, "baidu");
        Assert::contains($cli2->body, "Tencent");
        $cli1->close();
        $cli2->close();
        echo "OK\n";
    }
});

Swoole\Event::wait();


?>
--EXPECT--
OK
