<?php
// Fork a child process and wait for it with Swoole\Process.
// Run: php examples/process/basic.php
$process = new Swoole\Process(function (Swoole\Process $worker) {
    echo 'hello from the child process' . PHP_EOL;
    $worker->exit(0);
});
$process->start();
Swoole\Process::wait(true);
