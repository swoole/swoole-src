<?php
// A Process\Pool starts a fixed number of worker processes.
// Run: php examples/process_pool/basic.php (press Ctrl+C to stop)
$pool = new Swoole\Process\Pool(2);
$pool->on('WorkerStart', function ($pool, $workerId) {
    echo "worker $workerId started" . PHP_EOL;
});
$pool->start();
