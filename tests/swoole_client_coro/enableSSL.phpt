--TEST--
swoole_client_coro: enableSSL
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;

use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->connect('www.baidu.com', 443);
    $client->enableSSL();

    $http = "GET / HTTP/1.0\r\nAccept: */*User-Agent: Lowell-Agent\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n";
    if (!$client->send($http)) {
        echo "ERROR\n";
    }

    $content = '';
    while (true) {
        $read = $client->recv();
        if (empty($read)) {
            break;
        }
        $content .= $read;
    }
    $client->close();
    Assert::assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
