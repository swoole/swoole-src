--TEST--
swoole_http_client_coro: http client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function(){
    $cli = new Swoole\Coroutine\Http\Client('www.baidu.com');
    $cli->set(['timeout' => 10]);
    $cli->setBasicAuth('name','passwd');
    $cli->setHeaders([
        'Host' => 'www.baidu.com',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $ret = ($cli->get('/'));
    echo("OK\n");
});
?>
--EXPECT--
OK
