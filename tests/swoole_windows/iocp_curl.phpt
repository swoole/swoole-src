--TEST--
swoole_windows: iocp curl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!extension_loaded('curl')) {
    die('skip curl extension not loaded');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_CURL);

run(function (): void {
    $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    try {
        if (!Assert::true($server->bind('127.0.0.1', 0))) {
            return;
        }
        if (!Assert::true($server->listen())) {
            return;
        }

        $address = $server->getsockname();
        if (!Assert::isArray($address)) {
            return;
        }
        if (!Assert::greaterThan($address['port'], 0)) {
            return;
        }
        $port = $address['port'];

        $completed = new Swoole\Coroutine\Channel(1);
        go(function () use ($server, $completed): void {
            try {
                $connection = $server->accept(5);
                if (!Assert::assert($connection !== false, 'failed to accept http request')) {
                    return;
                }
                try {
                    $request = '';
                    while (!str_contains($request, "\r\n\r\n")) {
                        $chunk = $connection->recv(1024, 5);
                        if (!Assert::assert($chunk !== false && $chunk !== '', 'failed to read http request')) {
                            return;
                        }
                        $request .= $chunk;
                    }
                    Assert::contains($request, 'GET / HTTP/1.1');

                    $response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPONG\n";
                    Assert::same($connection->sendAll($response, 5), strlen($response));
                } finally {
                    $connection->close();
                }
            } finally {
                $completed->push(true);
            }
        });

        $ch = curl_init();
        Assert::isInstanceOf($ch, Swoole\Curl\Handler::class);
        try {
            curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:' . $port . '/');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);

            $body = curl_exec($ch);
            Assert::same($body, "PONG\n");
            Assert::same(curl_getinfo($ch, CURLINFO_HTTP_CODE), 200);
        } finally {
            curl_close($ch);

            $acceptCompleted = $completed->pop(6);
            Assert::same($acceptCompleted, true);
        }
    } finally {
        $server->close();
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
