--TEST--
swoole_http_client_coro: https client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip online test");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Http\Client('www.baidu.com', 443, true);
    $cli->set(['timeout' => 10]);
    $cli->setHeaders([
        'Host' => 'www.baidu.com',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $ret = ($cli->get('/'));
    if (!$ret) {
        echo("ERROR\n");
        var_dump($cli->errCode);
        return;
    } else {
        echo("OK\n");
        $cli->close();
    }
});
swoole_event::wait();
?>
--EXPECT--
OK
