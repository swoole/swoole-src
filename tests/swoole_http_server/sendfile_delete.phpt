--TEST--
swoole_http_server: sendfile delete_file removes the file at native transfer completion
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

// Large enough that an 8 MiB transfer cannot complete within one 128 KiB client
// buffer, so the opted-in file is still present while the reactor owns the transfer.
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
    $delete_path = tempnam('/tmp', 'swoole_sendfile_delete_');
    $keep_path   = tempnam('/tmp', 'swoole_sendfile_keep_');
    $content     = get_safe_random(CONTENT_SIZE);
    file_put_contents($delete_path, $content);
    file_put_contents($keep_path, $content);
    $submitted = new Atomic(0);

    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $delete_path, $keep_path, $content, $submitted, $wait_gone) {
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
        Co\run(function () use ($pm, $delete_path, $keep_path, $content, $submitted, $wait_gone) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set(['socket_buffer_size' => 128 * 1024]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            $client->send("GET /delete HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

            // Wait until the worker has returned from Response::sendfile().
            $deadline = microtime(true) + 5;
            while ($submitted->get() === 0 && microtime(true) < $deadline) {
                System::sleep(0.01);
            }
            Assert::same($submitted->get(), 1);

            // The first chunk has arrived but the transfer is far from complete, so the
            // opted-in file must still exist: deletion is tied to native completion, not
            // to the worker call returning.
            $response = $client->recv();
            Assert::notEmpty($response);
            clearstatcache(true, $delete_path);
            Assert::true(is_file($delete_path));

            while (true) {
                $chunk = $client->recv();
                if ($chunk === '' || $chunk === false) {
                    break;
                }
                $response .= $chunk;
            }
            $client->close();

            $body = substr($response, strpos($response, "\r\n\r\n") + 4);
            Assert::same($body, $content);
            Assert::true($wait_gone($delete_path));

            // The default keeps the file after a successful transfer.
            $keep_body = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/keep");
            Assert::same($keep_body, $content);
            clearstatcache(true, $keep_path);
            Assert::true(is_file($keep_path));
        });
        $pm->kill();
        @unlink($delete_path);
        @unlink($keep_path);
    };
    $pm->childFunc = function () use ($pm, $mode, $delete_path, $keep_path, $submitted) {
        $http = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Request $request, Response $response) use ($delete_path, $keep_path, $submitted) {
            if ($request->server['request_uri'] === '/delete') {
                $response->sendfile($delete_path, 0, 0, true);
                $submitted->set(1);
            } else {
                $response->sendfile($keep_path);
            }
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
