--TEST--
swoole_http_client_coro: upgrade bug
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $host = 'www.imiphp.com';
    $cli = new Swoole\Coroutine\Http\Client($host, 80);
    $cli->set(['timeout' => 10]);
    $cli->setHeaders([
        'Host' => $host,
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language' => 'zh-CN,zh;q=0.9',
        'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36 Core/1.63.5478.400 QQBrowser/10.1.1550.400',
        'Accept-Encoding' => 'gzip',
    ]);
    $ret = $cli->get('/');
    assert($ret);
    assert(strpos($cli->body, 'Swoole') !== false);
});
?>
--EXPECT--