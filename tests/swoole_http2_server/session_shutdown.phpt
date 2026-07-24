--TEST--
swoole_http2_server: session teardown after a fatal request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
display_errors=0
log_errors=0
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

$worker_error_signal = new Atomic(0);
$worker_error_fired = new Atomic(0);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $worker_error_signal, $worker_error_fired) {
    Coroutine\run(function () use ($pm, $worker_error_signal, $worker_error_fired) {
        // Leave an HTTP/2 session in the map by letting a suspended request coroutine be cancelled.
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        $client->set(['timeout' => 5]);
        Assert::true($client->connect());
        $request = new Http2Request;
        $request->path = '/crash';
        Assert::greaterThan($client->send($request), 0);

        // The uncaught cancellation must not become a late nghttp2 SIGSEGV.
        $deadline = microtime(true) + 5;
        while ($worker_error_fired->get() === 0 && microtime(true) < $deadline) {
            Coroutine::sleep(0.05);
        }
        Assert::same($worker_error_fired->get(), 1);
        Assert::same($worker_error_signal->get(), 0);

        // The replacement worker keeps the server usable on a fresh connection.
        $healthy = false;
        $deadline = microtime(true) + 5;
        while (microtime(true) < $deadline) {
            $client = new Client('127.0.0.1', $pm->getFreePort(), false);
            $client->set(['timeout' => 5]);
            if ($client->connect()) {
                $request = new Http2Request;
                $request->path = '/health';
                if ($client->send($request) > 0 && ($response = $client->recv()) && $response->data === 'OK') {
                    $healthy = true;
                    break;
                }
            }
            Coroutine::sleep(0.05);
        }
        Assert::true($healthy);
        echo "DONE\n";
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $worker_error_signal, $worker_error_fired) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'enable_coroutine' => true,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('workerError', function ($server, $worker_id, $worker_pid, $exit_code, $signal) use (
        $worker_error_signal,
        $worker_error_fired
    ) {
        $worker_error_signal->set($signal);
        $worker_error_fired->set(1);
    });
    $server->on('request', function (Request $request, Response $response) {
        if ($request->server['request_uri'] === '/crash') {
            $cid = Coroutine::getCid();
            Coroutine::create(function () use ($cid) {
                Coroutine::sleep(0.05);
                Coroutine::cancel($cid, true);
            });
            Coroutine::sleep(10);
            return;
        }
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
