--TEST--
swoole_process/coro: ipc with coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$proc1 = new \swoole_process(function (swoole_process $proc) {
    $socket = $proc->exportSocket();
    echo $socket->recv();
    $socket->send("hello proc2\n");
    echo "proc1 stop\n";
}, false, 1, true);

Assert::assert($proc1->start());

$proc2 = new \swoole_process(function (swoole_process $proc) use ($proc1) {
    Co::sleep(0.01);
    $socket = $proc1->exportSocket();
    $socket->send("hello proc1\n");
    echo $socket->recv();
    echo "proc2 stop\n";
}, false, 0, true);

Assert::assert($proc2->start());

swoole_process::wait(true);
swoole_process::wait(true);

?>
--EXPECT--
hello proc1
proc1 stop
hello proc2
proc2 stop
