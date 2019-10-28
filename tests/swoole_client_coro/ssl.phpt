--TEST--
swoole_client_coro: ssl client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
    if (!$cli->connect('www.baidu.com', 443)) {
        echo "ERROR\n";
    }

    $http = "GET / HTTP/1.0\r\nAccept: */*User-Agent: Lowell-Agent\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n";
    if (!$cli->send($http)) {
        echo "ERROR\n";
    }

    $content = '';
    while (true) {
        $read = $cli->recv();
        if (empty($read)) {
            break;
        }
        $content .= $read;
    }
    $cli->close();
    Assert::assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
