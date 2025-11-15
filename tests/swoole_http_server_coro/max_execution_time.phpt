--TEST--
swoole_http_server_coro: max execution time
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;
use Swoole\Coroutine\CanceledException;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $result = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}");
        var_dump($result);
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->set(['max_execution_time' => 1]);
        $server->handle('/', function ($request, $response) {
            try {
                sleep(3);
                $response->end("<h1>Index</h1>");
            } catch (\Throwable $e) {
                Assert::true($e instanceof CanceledException);
                $response->end('execution timeout');
            }
        });

        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
string(17) "execution timeout"
