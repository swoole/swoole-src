--TEST--
swoole_server_port: connections
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Scheduler;
use Swoole\Coroutine\System;
use Swoole\WebSocket\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm) {
    $sch = new Scheduler();
    $conns_1 = [];
    $conns_2 = [];

    $sch->parallel(
        3,
        function () use ($pm, &$conns_1) {
            $c = new Client(TCP_SERVER_HOST, $pm->getFreePort(0));
            $c->upgrade('/');
            $conns_1[] = $c->recv()->data;
            $c->recv();
        }
    );
    $sch->parallel(
        2,
        function () use ($pm, &$conns_2) {
            $c = new Client(TCP_SERVER_HOST, $pm->getFreePort(1));
            $c->upgrade('/');
            $conns_2[] = $c->recv()->data;
            $c->recv();
        }
    );

    // all
    $sch->add(
        function () use ($pm, &$conns_1, &$conns_2) {
            $c = new Client(TCP_SERVER_HOST, $pm->getFreePort(0));
            $c->upgrade('/');
            $conns_1[] = $c->recv()->data;

            $c->push('all');
            $frame = $c->recv();
            Assert::assert($frame);
            $json = json_decode($frame->data);
            Assert::eq($json->count, 8);

            $list1 = array_arrange($json->list);
            $list2 = array_arrange(array_merge($conns_1, $conns_2));

            Assert::eq($list1, $list2);
        }
    );

    // port-0
    $sch->add(
        function () use ($pm, &$conns_1) {
            $c = new Client(TCP_SERVER_HOST, $pm->getFreePort(0));
            $c->upgrade('/');
            $conns_1[] = $c->recv()->data;
            $c->push('port-0');
            $frame = $c->recv();
            Assert::assert($frame);
            $json = json_decode($frame->data);
            Assert::eq($json->count, 5);
            Assert::eq($json->list, $conns_1);
        }
    );

    // port-1
    $sch->add(
        function () use ($pm, &$conns_2) {
            $c = new Client(TCP_SERVER_HOST, $pm->getFreePort(1));
            $c->upgrade('/');
            $conns_2[] = $c->recv()->data;
            $c->push('port-1');
            $frame = $c->recv();
            Assert::assert($frame);
            $json = json_decode($frame->data);
            Assert::eq($json->count, 3);
            Assert::eq($json->list, $conns_2);
        }
    );

    $sch->add(
        function () use ($pm) {
            System::sleep(.5);
            $pm->kill();
        }
    );
    $sch->start();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('0.0.0.0', $pm->getFreePort(0), SWOOLE_PROCESS);
    $server->set([
        Constant::OPTION_LOG_FILE => '/dev/null',
        Constant::OPTION_WORKER_NUM => 1,
    ]);
    $server->on('open', function (Server $server, $request) {
        $server->push($request->fd, $request->fd);
    });
    $server->on(
        Constant::EVENT_WORKER_START,
        function () use ($pm) {
            $pm->wakeup();
        }
    );

    $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);

    $server->on(
        'message',
        function (Server $server, $frame) {
            if ($frame->data == 'all') {
                $iterator = $server->connections;
            } elseif ($frame->data == 'port-0') {
                $iterator = $server->ports[0]->connections;
            } elseif ($frame->data == 'port-1') {
                $iterator = $server->ports[1]->connections;
            } else {
                return;
            }

            $data['count'] = count($iterator);
            $data['list'] = array_values(iterator_to_array($iterator));
            $server->push($frame->fd, json_encode($data));
        }
    );

    $server->on('close', function ($ser, $fd) {});

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
