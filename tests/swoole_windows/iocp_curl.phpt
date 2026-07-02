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

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_CURL);

    run(function () use ($pm) {
        $ch = curl_init();
        Assert::isInstanceOf($ch, Swoole\Curl\Handler::class);

        curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:' . $pm->getFreePort() . '/');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);

        $body = curl_exec($ch);
        Assert::same($body, "PONG\n");
        Assert::same(curl_getinfo($ch, CURLINFO_HTTP_CODE), 200);
        curl_close($ch);
    });

    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $port = $pm->getFreePort();
    $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
    Assert::assert($server !== false, $errstr ?: 'failed to create socket server');
    $pm->wakeup();

    $conn = stream_socket_accept($server, 10);
    Assert::assert($conn !== false, 'failed to accept http request');

    $request = '';
    while (!str_contains($request, "\r\n\r\n")) {
        $chunk = fread($conn, 1024);
        if ($chunk === '' || $chunk === false) {
            break;
        }
        $request .= $chunk;
    }
    Assert::contains($request, 'GET / HTTP/1.1');

    fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPONG\n");
    fclose($conn);
    fclose($server);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
