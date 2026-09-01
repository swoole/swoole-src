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
use Swoole\Coroutine\System;
use Swoole\Runtime;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager();
$pm->setParentSetup(function () {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
});
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $handle = curl_init('http://127.0.0.1:' . $pm->getFreePort() . '/');
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
};
$pm->childFunc = function () use ($pm) {
    $port = $pm->getFreePort();
    $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errorCode, $errorMessage);
    Assert::assert($server !== false, $errorMessage ?: 'failed to create HTTP server');
    $pm->wakeup();

    $connection = stream_socket_accept($server, 2);
    Assert::assert($connection !== false, 'failed to accept HTTP request');
    stream_set_timeout($connection, 1);
    $request = '';
    while (!str_contains($request, "\r\n\r\n") && !feof($connection)) {
        $chunk = fread($connection, 1024);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
    }
    usleep(200000);
    @fwrite($connection, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPONG\n");
    fclose($connection);
    fclose($server);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
