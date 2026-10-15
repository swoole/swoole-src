--TEST--
swoole_http_server: release the cached addresses of keep-alive connections closed by the client in process mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

const N = 500;

$ips = get_server_ips();

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $ips) {
    Co\run(function () use ($pm, $ips) {
        // the server closes these connections so it does not cache their addresses
        $memory = function () use ($pm, $ips): int {
            return (int) httpGetBody("http://{$ips[1]}:{$pm->getFreePort()}/memory", [
                'headers' => ['Connection' => 'close'],
            ]);
        };
        $before = $memory();
        for ($i = 0; $i < N; $i++) {
            $client = new Client($ips[1], $pm->getFreePort());
            Assert::true($client->get('/'));
            Assert::eq($client->body, $ips[1]);
            $client->close();
        }
        // let the worker handle the close events
        Co::sleep(0.5);
        $after = $memory();
        // a connection that keeps both cached addresses holds at least 64 bytes
        Assert::lessThan($after - $before, N * 16);
    });
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        if ($request->server['request_uri'] === '/memory') {
            $response->end((string) memory_get_usage());
        } else {
            $response->end($request->server['remote_addr']);
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
