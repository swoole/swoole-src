--TEST--
swoole_websocket_server: message size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;

const N = 8;
$count = 0;
$pm = new SwooleTest\ProcessManager;

function test(Client $cli, $min, $max)
{
    global $count;
    $len = mt_rand($min, $max);
    $data = get_safe_random($len);
    for ($n = N; $n--;) {
        $cli->push($data);
        $ret = $cli->recv();
        if (Assert::eq($ret->data, $data)) {
            $count++;
        }
    }
}

$pm->parentFunc = function (int $pid) use ($pm) {
    for ($c = N; $c--;) {
        go(function () use ($pm) {
            $cli = new Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            test($cli, 64, 200);
            test($cli, 25600, 70000);
            test($cli, 70000, 400000);
        });
    }
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (Server $server, Frame $frame) {
        $server->push($frame->fd, $frame->data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
