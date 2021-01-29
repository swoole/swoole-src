--TEST--
swoole_http_server: compression_min_length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;
use Swoole\Coroutine\Http\Client;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm)
{
    run(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->setHeaders(['Accept-Encoding' => 'gzip', ]);
        $cli->get('/?bytes=128');
        Assert::eq($cli->getHeaders()['content-encoding'], 'gzip');

        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->setHeaders(['Accept-Encoding' => 'gzip', ]);
        $cli->get('/?bytes=127');
        Assert::assert(!isset($cli->getHeaders()['content-encoding']));
    });
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm)
{
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->set(['compression_min_length' => 128,]);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function ($request, swoole_http_response $response) {
        $response->end(str_repeat('A', $request->get['bytes']));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
