--TEST--
swoole_process: sysv msgqueue capacity
--SKIPIF--
<?php
require __DIR__.'/../include/skipif.inc';
skip_if_darwin();
?>
--FILE--
<?php
require __DIR__.'/../include/bootstrap.php';


function callback_function(swoole_process $worker)
{
}

$process = new swoole_process('callback_function', false, false);
$process->useQueue(ftok(__DIR__, 1), 1, 1024 * 1024 * 64);

const N = 32 * 1024 * 1024;


$bytes = 0;
while ($bytes < N) {
    $data = RandStr::getBytes(rand(4000, 8000));
    $bytes += strlen($data);
    $process->push($data);
}

Assert::assert($process->statQueue()['queue_bytes'] > N);

$rd_bytes = 0;
while ($rd_bytes < N) {
    $recv = $process->pop();
    $rd_bytes += strlen($recv);
}

Assert::same($process->statQueue()['queue_bytes'], 0);

$process->freeQueue();
?>
--EXPECT--
