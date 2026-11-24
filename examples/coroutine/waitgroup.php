<?php
// WaitGroup blocks until every task has called done().
// Run: php examples/coroutine/waitgroup.php
use Swoole\Coroutine\WaitGroup;
use function Swoole\Coroutine\run;

run(function () {
    $wg = new WaitGroup();
    for ($i = 1; $i <= 3; $i++) {
        $wg->add();
        Swoole\Coroutine::create(function () use ($wg, $i) {
            Swoole\Coroutine\System::sleep(0.05);
            echo "task $i done" . PHP_EOL;
            $wg->done();
        });
    }
    $wg->wait();
    echo 'all tasks finished' . PHP_EOL;
});
