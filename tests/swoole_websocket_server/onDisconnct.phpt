--TEST--
swoole_websocket_server: onDisconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;
use Swoole\Coroutine\Http\Client;

$pm = new ProcessManager;

$pm->parentFunc = function (int $pid) use ($pm) {
    run(function () use ($pm) {
        $data = httpGetBody('http://127.0.0.1:' . $pm->getFreePort() . '/');
        Assert::contains($data, 'HTTP 400 Bad Request');

        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::assert($client->upgrade('/websocket'));
        Assert::eq($client->getStatusCode(), 101);
        $client->push('hello world');
        $client->close();
    });
    puts('done!');
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {
        if ($frame->data == 'shutdown') {
            $serv->disconnect($frame->fd, 4000, 'shutdown received');
        }
    });
    $serv->on('connect', function ($s, $id) use ($pm) {
        puts("connect ".$id);
    });
    $serv->on('disconnect', function ($s, $id) use ($pm) {
        puts("disconnect ".$id);
    });
    $serv->on('open', function ($s, $req) use ($pm) {
        puts("open ".$req->fd);
    });
    $serv->on('close', function ($s, $id) use ($pm) {
        puts("close ".$id);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
connect 1
disconnect 1
connect 2
open 2
close 2
done!
