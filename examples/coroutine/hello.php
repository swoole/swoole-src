<?php
// The simplest coroutine program: run() opens a coroutine context and waits
// for all tasks to finish. Run: php examples/coroutine/hello.php
use function Swoole\Coroutine\run;

run(function () {
    Swoole\Coroutine::create(function () {
        Swoole\Coroutine\System::sleep(0.1);
        echo 'first task done' . PHP_EOL;
    });
    Swoole\Coroutine::create(function () {
        Swoole\Coroutine\System::sleep(0.1);
        echo 'second task done' . PHP_EOL;
    });
    echo 'both tasks started' . PHP_EOL;
});
