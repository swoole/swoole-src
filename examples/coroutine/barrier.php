<?php
// Barrier waits until every coroutine holding it has finished.
// Run: php examples/coroutine/barrier.php
use Swoole\Coroutine\Barrier;
use function Swoole\Coroutine\run;

run(function () {
    $barrier = Barrier::make();
    for ($i = 1; $i <= 3; $i++) {
        Swoole\Coroutine::create(function () use ($barrier, $i) {
            Swoole\Coroutine\System::sleep(0.05);
            echo "task $i reached the barrier" . PHP_EOL;
        });
    }
    Barrier::wait($barrier);
    echo 'all tasks reached the barrier' . PHP_EOL;
});
