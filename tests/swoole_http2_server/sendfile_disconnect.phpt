--TEST--
swoole_http2_server: sendfile keeps the server alive when a client disconnects mid-transfer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

// Larger than the default 64 KiB flow-control window, so the transfer is still in
// progress when the client goes away.
$big_file = tempnam(sys_get_temp_dir(), 'swoole_sendfile_big_');
file_put_contents($big_file, str_repeat('swoole', 350000));

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $sendfile_finished = new Atomic(0);
    $worker_error_fired = new Atomic(0);

    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $sendfile_finished, $worker_error_fired) {
        Coroutine\run(function () use ($pm, $sendfile_finished, $worker_error_fired) {
            // Request the large file, then abandon the connection before draining it.
            $client = new Client('127.0.0.1', $pm->getFreePort(), false);
            $client->set(['timeout' => 10]);
            Assert::true($client->connect());
            $request = new Http2Request;
            $request->path = '/big';
            Assert::greaterThan($client->send($request), 0);
            $client->close();

            // A fresh connection is still served.
            $client = new Client('127.0.0.1', $pm->getFreePort(), false);
            $client->set(['timeout' => 10]);
            Assert::true($client->connect());
            $request = new Http2Request;
            $request->path = '/health';
            Assert::greaterThan($client->send($request), 0);
            $response = $client->recv();
            Assert::notEmpty($response);
            Assert::same($response->statusCode, 200);
            Assert::same($response->data, 'OK');

            // The worker that ran the abandoned sendfile must have returned normally
            // rather than crashed (which in process mode is masked by a worker restart).
            $deadline = microtime(true) + 5;
            while ($sendfile_finished->get() === 0 && $worker_error_fired->get() === 0 && microtime(true) < $deadline) {
                Coroutine::sleep(0.05);
            }
            Assert::same($sendfile_finished->get(), 1);
            Assert::same($worker_error_fired->get(), 0);
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $big_file, $sendfile_finished, $worker_error_fired) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'log_file' => '/dev/null',
            'open_http2_protocol' => true,
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('workerError', function () use ($worker_error_fired) {
            $worker_error_fired->set(1);
        });
        $server->on('request', function (Request $request, Response $response) use ($big_file, $sendfile_finished) {
            if ($request->server['request_uri'] === '/big') {
                $response->sendfile($big_file);
                $sendfile_finished->set(1);
                return;
            }
            $response->end('OK');
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

unlink($big_file);
echo "DONE\n";
?>
--EXPECT--
DONE
