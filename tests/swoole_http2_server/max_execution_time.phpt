--TEST--
swoole_http2_server: max execution time
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\CanceledException;

$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();
        $cli->send(new Swoole\Http2\Request);
        $response = $cli->recv();
        var_dump($response->data);
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_coroutine' => true,
        'max_execution_time' => 1,
        'hook_flags' => SWOOLE_HOOK_ALL
    ]);

    $http->on('start', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        try {
            sleep(3);
            $response->end("<h1>Index</h1>");
        } catch (\Throwable $e) {
            Assert::true($e instanceof CanceledException);
            $response->end('execution timeout');
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
string(17) "execution timeout"
