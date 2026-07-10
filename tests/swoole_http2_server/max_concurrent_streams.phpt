--TEST--
swoole_http2_server: max_concurrent_streams limit enforcement
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const MAX_STREAMS = 4;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        // Use a single connection and send more concurrent streams than allowed.
        // The server holds each request open for a while, so all streams stay active.
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 10]);
        Assert::true($cli->connect());

        $streamIds = [];
        $responses = [];

        // Send MAX_STREAMS requests (these should all succeed)
        for ($i = 0; $i < MAX_STREAMS; $i++) {
            $req = new Request;
            $req->method = 'GET';
            $req->path = '/';
            $streamId = $cli->send($req);
            Assert::greaterThan($streamId, 0);
            $streamIds[] = $streamId;
        }

        // Send additional requests exceeding the limit
        $exceeding_ids = [];
        for ($i = 0; $i < 4; $i++) {
            $req = new Request;
            $req->method = 'GET';
            $req->path = '/';
            $streamId = $cli->send($req);
            Assert::greaterThan($streamId, 0);
            $exceeding_ids[] = $streamId;
        }

        // Collect all responses
        $success_count = 0;
        $refused_count = 0;
        $total = MAX_STREAMS + 4;

        for ($i = 0; $i < $total; $i++) {
            $response = $cli->recv();
            if ($response === false) {
                // Connection may have been reset
                $refused_count++;
                break;
            }
            if ($response->statusCode === 200) {
                $success_count++;
            } elseif ($response->statusCode === 0 || $response->statusCode === -1) {
                // RST_STREAM received — stream was refused
                $refused_count++;
            } else {
                $refused_count++;
            }
        }

        // All initial streams within the limit should succeed
        Assert::greaterThanEq($success_count, MAX_STREAMS);
        // At least some exceeding streams should be refused
        Assert::greaterThan($refused_count, 0);

        $cli->close();
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http2_max_concurrent_streams' => MAX_STREAMS,
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        // Hold the stream open briefly to create concurrent stream pressure
        System::sleep(0.2);
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
