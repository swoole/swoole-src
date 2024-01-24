--TEST--
swoole_process_pool: message async [disable message bus]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process\Pool;
use Swoole\Coroutine\System;

const N = 256;

$in = $out = [];
for ($i = N; $i--;) {
    $in[] = random_bytes(random_int(1024, 8192));
}

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);
$pool->set([
    'enable_coroutine' => true,
]);

$pool->on(Constant::EVENT_WORKER_START, function (Pool $pool, int $workerId) use ($in) {
    if ($workerId == 0) {
        foreach ($in as $item) {
            Assert::true($pool->sendMessage($item, 1));
            System::sleep(0.002);
        }
    }
});

$pool->on(Constant::EVENT_MESSAGE, function ($pool, $data) use (&$out, $in) {
    $out[] = $data;
    if (count($out) == N) {
        Assert::eq($in, $out);
        echo "DONE\n";
        $pool->shutdown();
    }
});

$pool->start();
?>
--EXPECT--
DONE
