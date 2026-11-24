<?php
// Run a shell command in a coroutine; the process runs in a worker pool so
// the event loop stays responsive. Run: php examples/coroutine/system_exec.php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    $result = System::exec('echo hello-from-exec');
    echo 'exit code: ', $result['code'], PHP_EOL;
    echo 'output: ', trim($result['output']), PHP_EOL;
});
