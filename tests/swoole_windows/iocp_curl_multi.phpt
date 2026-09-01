--TEST--
swoole_windows: iocp native curl multi
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
use Swoole\Coroutine\Socket;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

const REQUESTS = 3;

$port = get_one_free_port();
Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () use ($port) {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Assert::true($server->bind('127.0.0.1', $port));
    Assert::true($server->listen());
    go(function () use ($server) {
        for ($requestIndex = 0; $requestIndex < REQUESTS; $requestIndex++) {
            $connection = $server->accept();
            Assert::isInstanceOf($connection, Socket::class);
            $request = $connection->recv();
            Assert::assert((bool) preg_match('#GET /(\d+) HTTP/#', $request, $matches));
            $body = "PONG-{$matches[1]}\n";
            $connection->sendAll(
                "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n{$body}"
            );
            $connection->close();
        }
        $server->close();
    });

    $multi = curl_multi_init();
    $handles = [];
    for ($index = 0; $index < REQUESTS; $index++) {
        $handle = curl_init('http://127.0.0.1:' . $port . '/' . $index);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_CONNECTTIMEOUT_MS, 1000);
        curl_setopt($handle, CURLOPT_TIMEOUT_MS, 2000);
        curl_multi_add_handle($multi, $handle);
        $handles[$index] = $handle;
    }

    do {
        $status = curl_multi_exec($multi, $running);
    } while ($status === CURLM_CALL_MULTI_PERFORM);

    while ($running && $status === CURLM_OK) {
        if (curl_multi_select($multi, 1.0) === -1) {
            Swoole\Coroutine\System::sleep(0.001);
        }
        do {
            $status = curl_multi_exec($multi, $running);
        } while ($status === CURLM_CALL_MULTI_PERFORM);
    }

    Assert::same($status, CURLM_OK);
    foreach ($handles as $index => $handle) {
        Assert::same(curl_multi_getcontent($handle), "PONG-{$index}\n");
        Assert::same(curl_getinfo($handle, CURLINFO_HTTP_CODE), 200);
        curl_multi_remove_handle($multi, $handle);
        curl_close($handle);
    }
    curl_multi_close($multi);
});

echo "DONE\n";
?>
--EXPECT--
DONE
