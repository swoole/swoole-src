--TEST--
swoole_windows: cancel native curl running on iocp
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

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use Swoole\Coroutine\System;
use Swoole\Runtime;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

$port = get_one_free_port();
Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () use ($port) {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($server->bind('127.0.0.1', $port));
    Assert::true($server->listen());
    go(function () use ($server) {
        $connection = $server->accept();
        Assert::isInstanceOf($connection, Socket::class);
        $connection->recv();
        System::sleep(0.2);
        $connection->sendAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPONG\n");
        $connection->close();
        $server->close();
    });

    $handle = curl_init('http://127.0.0.1:' . $port . '/');
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($handle, CURLOPT_CONNECTTIMEOUT_MS, 1000);
    curl_setopt($handle, CURLOPT_TIMEOUT_MS, 2000);

    $coroutineId = Coroutine::getCid();
    go(function () use ($coroutineId) {
        System::sleep(0.02);
        Assert::true(Coroutine::cancel($coroutineId));
    });

    Assert::false(curl_exec($handle));
    Assert::same(curl_errno($handle), CURLE_ABORTED_BY_CALLBACK);
    Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
    curl_close($handle);
});

echo "DONE\n";
?>
--EXPECT--
DONE
