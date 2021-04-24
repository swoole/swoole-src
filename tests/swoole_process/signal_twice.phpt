--TEST--
swoole_process: signal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Process;
use function Swoole\Coroutine\run;

const N = 2;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $n = N;
    while($n--) {
        Process::kill($pid, SIGUSR1);
        $pm->wait();
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $n = N;
    while($n--) {
        run(static function () use($n, $pm){
            $running = true;
            Process::signal(SIGUSR1, function() use(&$running, $n) {
                $running = false;
                echo 'sigusr1 one-'.$n.PHP_EOL;
            });
            $pm->wakeup();
            go(static function () use(&$running) {
                while ($running) {
                    Co::sleep(0.1);
                }
            });
        });
    }
    $pm->wakeup();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
sigusr1 one-1
sigusr1 one-0
