--TEST--
swoole_process: deamon
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $proc) {
    $r = \Swoole\Process::daemon();
    Assert::assert($r);

    $proc->push(posix_getpid());
});
$proc->useQueue();
$forkPid = $proc->start();
$demonPid = intval($proc->pop());

Assert::assert($forkPid !== $demonPid);

\Swoole\Process::kill($demonPid, SIGKILL);

\Swoole\Process::wait(true);
\Swoole\Process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
