--TEST--
swoole_coroutine: signal listener
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Process;

ini_set('swoole.enable_coroutine', 'off');

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($n = 3; $n--;) {
        $ret = Process::wait(false);
        Assert::isEmpty($ret);
        switch_process();
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $pm->wakeup();
    Coroutine::set([
        'exit_condition' => function () {
            return Coroutine::stats()['signal_listener_num'] === 0;
        }
    ]);
    Process::signal(SIGTERM, function () {
        echo 'SIGTERM' . PHP_EOL;
        Process::signal(SIGTERM, null);
        exit(123);
    });
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(123);

?>
--EXPECT--
SIGTERM
