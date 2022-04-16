--TEST--
swoole_process: wait signal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Event;

ini_set('serialize_precision', -1);
ini_set('precision', -1);

$proc = new Process(function(Process $process) {
    swoole_async_set(['wait_signal' => true]);
    Process::signal(SIGINT, function () {
        echo "SIGINT\n";
        Process::signal(SIGINT, null);
    });
    echo "START\n";
    Event::wait();
}, true, true);

$r = $proc->start();
Assert::assert($r > 0);

echo $proc->read();
Process::kill($r, SIGINT);
echo $proc->read();

$retval = Process::wait(true);
Assert::eq($retval['pid'], $r);
Assert::eq($retval['code'], 0);
Assert::eq($retval['signal'], 0);
?>
--EXPECT--
START
SIGINT
