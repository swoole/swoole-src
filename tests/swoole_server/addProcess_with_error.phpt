--TEST--
swoole_server: addProcess with fatal error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$atomic = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {

    class Process4 extends Swoole\Process
    {
        public function __construct()
        {
            parent::__construct([$this, 'run']);
        }

        public function run()
        {
            go(function () {
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

    $server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set(['log_file' => '/dev/null']);
    $server->on('packet', function () { });
    $server->addProcess(new Process4);
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_error.php on line 31
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_error.php on line 31
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_error.php on line 31
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_error.php on line 31
sleep start then sleep end

Fatal error: ERROR in %s/tests/swoole_server/addProcess_with_error.php on line 31
DONE
