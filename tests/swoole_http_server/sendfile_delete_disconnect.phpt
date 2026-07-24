--TEST--
swoole_http_server: sendfile delete_file removes the file when the client disconnects mid-transfer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine\Client;
use Swoole\Coroutine\System;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Runtime;

const CONTENT_SIZE = 8 * 1024 * 1024;

$wait_gone = function (string $path): bool {
    for ($i = 0; $i < 200; $i++) {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            return true;
        }
        System::sleep(0.025);
    }
    return false;
};

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $delete_path = tempnam('/tmp', 'swoole_sendfile_disconnect_');
    file_put_contents($delete_path, get_safe_random(CONTENT_SIZE));
    $submitted = new Atomic(0);

    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $delete_path, $submitted, $wait_gone) {
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
        Co\run(function () use ($pm, $delete_path, $submitted, $wait_gone) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set(['socket_buffer_size' => 128 * 1024]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            $client->send("GET /delete HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

            $deadline = microtime(true) + 5;
            while ($submitted->get() === 0 && microtime(true) < $deadline) {
                System::sleep(0.01);
            }
            Assert::same($submitted->get(), 1);

            // Take only the first chunk, then abandon the connection mid-transfer.
            Assert::notEmpty($client->recv());
            $client->close();

            // The connection/output buffer is destroyed with an incomplete transfer, and
            // the opted-in file is still removed.
            Assert::true($wait_gone($delete_path));

            // The server stays available for a fresh request.
            Assert::same(file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/health"), 'OK');
        });
        $pm->kill();
        @unlink($delete_path);
    };
    $pm->childFunc = function () use ($pm, $mode, $delete_path, $submitted) {
        $http = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Request $request, Response $response) use ($delete_path, $submitted) {
            if ($request->server['request_uri'] === '/health') {
                $response->end('OK');
                return;
            }
            $response->sendfile($delete_path, 0, 0, true);
            $submitted->set(1);
        });
        $http->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
