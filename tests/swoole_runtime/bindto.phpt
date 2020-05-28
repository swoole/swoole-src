--TEST--
swoole_runtime: socket context bindto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Runtime;

use function Swoole\Coroutine\run;
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine();

    run(function () use($pm) {
        $context = stream_context_create([
            'socket' => [
                'bindto' => '0:9100',
            ],
        ]);

        file_get_contents("http://127.0.0.1:{$pm->getFreePort()}", false, $context);
        $pm->kill();
        echo "Done\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            Assert::eq($request->server['remote_addr'], '127.0.0.1');
            Assert::eq($request->server['remote_port'], 9100);
            $response->end('success');
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
