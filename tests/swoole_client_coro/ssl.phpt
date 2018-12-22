--TEST--
swoole_client_coro: ssl client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (!defined("SWOOLE_SSL")) {
    echo "skip";
}
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
    assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
