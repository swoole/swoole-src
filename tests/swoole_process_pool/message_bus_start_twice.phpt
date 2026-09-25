--TEST--
swoole_process_pool: start message bus twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process\Pool;

$pool = new Pool(1, SWOOLE_IPC_UNIXSOCK);
$pool->set([
    'enable_message_bus' => true,
]);

$pool->on(Constant::EVENT_WORKER_START, function (Pool $pool) {
    Assert::true($pool->sendMessage('hello', 0));
});

$pool->on(Constant::EVENT_MESSAGE, function (Pool $pool, string $data) {
    Assert::same($data, 'hello');
    echo "DONE\n";
    $pool->shutdown();
});

$pool->start();
$pool->start();
?>
--EXPECT--
DONE
DONE
