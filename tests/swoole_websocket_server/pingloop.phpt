--TEST--
swoole_websocket_server: ping loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const PING_INTERVAL = 100; // (ms), just for test, don't need to be so fast!
const PING_LOOP = 5;

$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($i = MAX_CONCURRENCY_MID; $i--;) {
        go(function () use ($pm) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            $loop = 0;
            while ($response = $cli->recv(-1)) {
                switch ($response->opcode) {
                    case WEBSOCKET_OPCODE_PING:
                        global $count;
                        $count++;
                        $loop++;
                        if (mt_rand(0, 1)) {
                            $pong = new swoole_websocket_frame;
                            $pong->opcode = WEBSOCKET_OPCODE_PONG;
                            $ret = $cli->push($pong);
                        } else {
                            $ret = $cli->push('', WEBSOCKET_OPCODE_PONG);
                        }
                        Assert::assert($ret);
                        break;
                    case WEBSOCKET_OPCODE_CLOSE:
                        break 2;
                    default:
                        Assert::assert(0, 'never hear.');
                }
            }
            Assert::same($loop, PING_LOOP);
        });
    }
    swoole_event_wait();
    global $count;
    Assert::same($count, PING_LOOP * MAX_CONCURRENCY_MID);
    $pm->kill();
    echo "DONE";
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('workerStart', function (swoole_websocket_server $server) use ($pm) {
        $timer_id = $server->tick(PING_INTERVAL, function () use ($server) {
            foreach ($server->connections as $fd) {
                if (mt_rand(0, 1)) {
                    $ping = new swoole_websocket_frame;
                    $ping->opcode = WEBSOCKET_OPCODE_PING;
                    $server->push($fd, $ping);
                } else {
                    $server->push($fd, '', WEBSOCKET_OPCODE_PING);
                }
            }
        });
        $server->after(PING_LOOP * PING_INTERVAL, function () use ($pm, $server, $timer_id) {
            $server->clearTimer($timer_id);
            foreach ($server->connections as $fd) {
                $server->push($fd, new swoole_websocket_closeframe);
            }
        });
        $pm->wakeup();
    });
    $serv->on('open', function ($server, $req) { });
    $serv->on('message', function ($server, swoole_websocket_frame $frame) {
        Assert::same($frame->opcode, WEBSOCKET_OPCODE_PONG);
    });
    $serv->on('close', function ($server, $fd) { });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
