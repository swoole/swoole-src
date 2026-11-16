--TEST--
swoole_http_client_coro: #2611 bound error with dns resolve and cross close
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('localhost', $pm->getFreePort());
        for ($i = 0; $i < 2; $i++) {
            go(function () use ($client) {
                $client->get('/');
                $client->close();
            });
        }
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        Co::sleep(1);
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: Socket#%d has already been bound to another coroutine#%d, reading or writing of the same socket in coroutine#%d at the same time is not allowed in %s:%d
%A
