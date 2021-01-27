--TEST--
swoole_socket_coro: ssl client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function () {
    $cli = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    $cli->setProtocol(['open_ssl' => true,]);

    if (!$cli->connect('www.baidu.com', 443)) {
        echo "ERROR\n";
    }

    $http = "GET / HTTP/1.1\r\nAccept: */*User-Agent: Lowell-Agent\r\nHost: www.baidu.com\r\nConnection: Keep-Alive\r\n"
        . "Keep-Alive: on\r\n\r\n";
    if (!$cli->send($http)) {
        echo "ERROR\n";
    }

    $content = '';
    $length = 0;
    while (true) {
        $read = $cli->recv();
        if (empty($read)) {
            var_dump($read);
            break;
        }
        $content .= $read;
        if ($length == 0) {
            if (preg_match('#Content-Length: (\d+)#i', $content, $match)) {
                $length = intval($match[1]);
            }
        }
        $header_length = strpos($content, "\r\n\r\n");
        if (strlen($content) == $length + $header_length + 4) {
            break;
        }
    }
    $cli->close();
    Assert::assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
