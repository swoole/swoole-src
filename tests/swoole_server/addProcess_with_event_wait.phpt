--TEST--
swoole_server: addProcess with event wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(-1);
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {

    class Process5 extends Swoole\Process
    {
        public function __construct()
        {
            parent::__construct([$this, 'run']);
        }

        public function run()
        {
            swoole_timer_tick(100, function (int $id) use (&$i) {
                global $pm;
                if (++$i === 10) {
                    swoole_timer_clear($id);
                    $pm->wakeup();
                }
                echo "Tick {$i}\n";
            });
        }
    }

    $server = new Swoole\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set(['log_file' => '/dev/null']);
    $server->on('packet', function () { });
    $server->addProcess(new Process5);
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Tick 1
Tick 2
Tick 3
Tick 4
Tick 5
Tick 6
Tick 7
Tick 8
Tick 9
Tick 10
