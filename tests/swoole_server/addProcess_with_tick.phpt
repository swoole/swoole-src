--TEST--
swoole_server: addProcess with swoole_timer_tick fatal error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$atomic = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;

class Process3 extends Swoole\Process
{
    public function __construct()
    {
        parent::__construct([$this, 'run']);
    }

    public function run()
    {
        swoole_timer_tick(100, function () {
            global $atomic;
            if ($atomic->add() > 5) {
                global $pm;
                $pm->wakeup();
                Co::yield();
                return;
            }
            echo "sleep start then ";
            Co::sleep(0.01);
            echo "sleep end\n";
            trigger_error('ERROR', E_USER_ERROR);
        });
    }
}

$pm->parentFunc = function () use ($pm) {
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set([
        'log_file' => '/dev/null',
//        'worker_num' => 1,
    ]);
    $server->on('packet', function () {
    });
    $server->addProcess(new Process3);
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_tick.php on line %d
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_tick.php on line %d
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_tick.php on line %d
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_tick.php on line %d
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_tick.php on line %d
DONE
