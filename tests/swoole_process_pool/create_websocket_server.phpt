--TEST--
swoole_process_pool: create websocket server in process pool
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Server;

use function Swoole\Coroutine\run;

$workerNum = 2;
$port = get_one_free_port();

$pool = new Swoole\Process\Pool($workerNum);

$pool->on("WorkerStart", function ($pool, $workerId) use ($port) {
    if ($workerId === 0) {
        $server = new Server('127.0.0.1', $port);
        $server->on("message", function ($server, $frame) {
            $server->push($frame->fd, $frame->data);
        });
        $server->start();
    } elseif ($workerId === 1) {
        run(function () use ($port, $pool) {
            $client = new Client('127.0.0.1', $port);
            while (!$client->upgrade('/')) {}
            $data = 'data';
            $client->push($data);
            $frame = $client->recv();
            Assert::eq($frame->data, $data);
            $pool->shutdown();
        });
    }
});

$pool->start();
echo "DONE\n";
?>
--EXPECTF--
[%s]	INFO	Server is shutdown now
DONE
