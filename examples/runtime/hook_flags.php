<?php
// Runtime hooks turn blocking PHP calls (sleep, file, PDO, ...) into
// coroutine-friendly ones. Run: php examples/runtime/hook_flags.php
use Swoole\Coroutine\WaitGroup;
use function Swoole\Coroutine\run;

Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);

run(function () {
    $wg = new WaitGroup();
    $start = microtime(true);
    for ($i = 0; $i < 2; $i++) {
        $wg->add();
        Swoole\Coroutine::create(function () use ($wg) {
            usleep(100000);
            $wg->done();
        });
    }
    $wg->wait();
    echo 'two 0.1s sleeps overlap: ',
        sprintf('%.2f', microtime(true) - $start), 's elapsed', PHP_EOL;
});
