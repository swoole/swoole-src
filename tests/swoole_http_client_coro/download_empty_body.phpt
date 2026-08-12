--TEST--
swoole_http_client_coro: empty download state does not affect the next request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$filename = '/tmp/swoole-http-client-empty-download-' . getmypid();
file_put_contents($filename, 'unchanged');

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $filename) {
    Co\run(function () use ($pm, $filename) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->download('/empty', $filename));
        Assert::true($client->get('/body'));
        Assert::same($client->body, 'response body');
        Assert::same(file_get_contents($filename), 'unchanged');
        $client->close();
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        if ($request->server['request_uri'] === '/empty') {
            $response->status(204);
            $response->end();
        } else {
            $response->end('response body');
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
@unlink($filename);
?>
--EXPECT--
DONE
