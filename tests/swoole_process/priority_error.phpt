--TEST--
swoole_process: priority [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

const PRIORITY = 12;

$process = new Process(function(Process $worker) {

}, false, false);

Assert::eq($process->getPriority(-1000, posix_getpid()), false);
Assert::eq(swoole_last_error(), SOCKET_EINVAL);

Assert::eq($process->setPriority(-1000, posix_getpid(), PRIORITY), false);
Assert::eq(swoole_last_error(), SOCKET_EINVAL);

Assert::eq(@$process->getPriority(PRIO_USER, null), false);
Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

Assert::eq(@$process->setPriority(PRIO_USER, PRIORITY, null), false);
Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

?>
--EXPECT--
