--TEST--
swoole_websocket_server: websocket with large data concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;

$count = 0;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            global $count;
            $cli = new Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            $len = mt_rand(35000, 40000);
            $data = get_safe_random($len);
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->push($data);
                $ret = $cli->recv();
                if (Assert::eq($ret->data, $data)) {
                    $count++;
                }
            }
            if (co::stats()['coroutine_num'] === 1) {
                Assert::same($count, (MAX_CONCURRENCY_MID * MAX_REQUESTS));
                $cli->push('max');
                Assert::assert((int)$cli->recv()->data > 1);
            }
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
        co::sleep(0.001);
        if ($frame->data === 'max') {
            $server->push($frame->fd, co::stats()['coroutine_peak_num']);
        } else {
            Assert::assert(strlen($frame->data) >= 35000);
            $server->push($frame->fd, $frame->data);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
