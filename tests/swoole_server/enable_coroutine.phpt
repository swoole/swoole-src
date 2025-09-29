--TEST--
swoole_server: reload with enable_coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Event;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Process;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    $list = [];
    go(function () use (&$list, $pm) {
        for ($i = 2; $i--;) {
            for ($n = 5; $n--;) {
                echo 'cid-' . httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/task?n={$n}") . "\n";
            }
            if ($i == 1) {
                Process::kill(file_get_contents(TEST_PID_FILE), SIGUSR1);
                $pm->wait();
            }
        }
    });
    Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => TEST_LOG_FILE,
        'pid_file' => TEST_PID_FILE,
        'worker_num' => 1,
    ]);
    $server->on('WorkerStart', function (Server $server, int $worker_id) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) {
        System::sleep(0.01);
        $response->end(co::getuid());
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
cid-2
cid-3
cid-4
cid-5
cid-6
cid-2
cid-3
cid-4
cid-5
cid-6
DONE
