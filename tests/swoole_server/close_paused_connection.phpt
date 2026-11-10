--TEST--
swoole_server: the heartbeat closes a paused connection and calls onClose
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $closes         = new Atomic(0);
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $closes) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 5);
        stream_set_timeout($client, 10);
        fwrite($client, 'hello');
        // onClose runs before the server closes the socket.
        Assert::same(stream_get_contents($client), '');
        Assert::false(stream_get_meta_data($client)['timed_out']);
        Assert::same($closes->get(), 1);
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $closes) {
        $serv = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $serv->set([
            'worker_num'               => 1,
            'log_file'                 => '/dev/null',
            'heartbeat_check_interval' => 1,
            'heartbeat_idle_time'      => 2,
        ]);
        $serv->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $serv->on('receive', function (Server $serv, int $fd) {
            Assert::true($serv->pause($fd));
        });
        $serv->on('close', function () use ($closes) {
            $closes->add();
        });
        $serv->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
