--TEST--
swoole_http2_server: max_headers limit enforcement
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;
use function Swoole\Coroutine\run;

const MAX_HEADERS = 10;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        // Test 1: Request within the limit should succeed
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        Assert::true($cli->connect());

        $req = new Request;
        $req->method = 'GET';
        $req->path = '/';
        $req->headers = [];
        // Add headers within the limit (pseudo-headers :method, :path, :scheme, :authority count too)
        // So we can add up to MAX_HEADERS - 4 custom headers safely
        for ($i = 0; $i < MAX_HEADERS - 5; $i++) {
            $req->headers["x-custom-{$i}"] = "value-{$i}";
        }

        $streamId = $cli->send($req);
        Assert::greaterThan($streamId, 0);
        $response = $cli->recv();
        Assert::eq($response->statusCode, 200);
        Assert::eq($response->data, 'OK');
        $cli->close();

        // Test 2: Request exceeding the limit should be rejected (connection reset)
        $cli2 = new Client('127.0.0.1', $pm->getFreePort());
        $cli2->set(['timeout' => 5]);
        Assert::true($cli2->connect());

        $req2 = new Request;
        $req2->method = 'GET';
        $req2->path = '/';
        $req2->headers = [];
        // Add more headers than the limit allows
        for ($i = 0; $i < MAX_HEADERS + 10; $i++) {
            $req2->headers["x-flood-{$i}"] = "value-{$i}";
        }

        $streamId2 = $cli2->send($req2);
        Assert::greaterThan($streamId2, 0);
        $response2 = $cli2->recv();
        // The server should have closed the stream or connection; response should be false or error
        Assert::assert($response2 === false || $response2->statusCode !== 200);
        $cli2->close();

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
        'http2_max_headers' => MAX_HEADERS,
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
