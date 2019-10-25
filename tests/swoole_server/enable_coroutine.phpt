--TEST--
swoole_server: reload with enable_coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        for ($i = 2; $i--;) {
            for ($n = 5; $n--;) {
                echo "cid-" . httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/task?n={$n}") . "\n";
            }
            if ($i == 1) {
                Swoole\Process::kill(file_get_contents(TEST_PID_FILE), SIGUSR1);
                usleep(100 * 1000);
            }
        }
    });
    Swoole\Event::wait();
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
    $server->on('WorkerStart', function (Swoole\Server $server, int $worker_id) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
        $response->end(\Co::getuid());
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
