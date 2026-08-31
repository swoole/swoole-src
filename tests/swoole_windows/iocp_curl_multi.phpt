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
use function Swoole\Coroutine\run;

const REQUESTS = 3;

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

    run(function () use ($pm) {
        $multi = curl_multi_init();
        $handles = [];
        for ($index = 0; $index < REQUESTS; $index++) {
            $handle = curl_init('http://127.0.0.1:' . $pm->getFreePort() . '/' . $index);
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
};
$pm->childFunc = function () use ($pm) {
    $port = $pm->getFreePort();
    $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errorCode, $errorMessage);
    Assert::assert($server !== false, $errorMessage ?: 'failed to create HTTP server');
    $pm->wakeup();

    for ($requestIndex = 0; $requestIndex < REQUESTS; $requestIndex++) {
        $connection = stream_socket_accept($server, 2);
        Assert::assert($connection !== false, 'failed to accept HTTP request');
        stream_set_timeout($connection, 1);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $chunk = fread($connection, 1024);
            if ($chunk === '' || $chunk === false) {
                break;
            }
            $request .= $chunk;
        }
        Assert::assert((bool) preg_match('#GET /(\d+) HTTP/#', $request, $matches));
        $body = "PONG-{$matches[1]}\n";
        fwrite($connection, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n{$body}");
        fclose($connection);
    }
    fclose($server);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
