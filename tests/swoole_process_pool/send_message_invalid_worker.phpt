--TEST--
swoole_process_pool: sendMessage invalid worker id
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process\Pool;

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);
$pool->set([
    'enable_coroutine' => true,
    'enable_message_bus' => true,
]);

$pool->on(Constant::EVENT_WORKER_START, function (Pool $pool, int $workerId) {
    if ($workerId !== 0) {
        return;
    }

    $errors = [];
    set_error_handler(function (int $errno, string $errstr) use (&$errors) {
        $errors[] = $errstr;
        return true;
    });

    Assert::false($pool->sendMessage('hello', -1));
    Assert::false($pool->sendMessage('hello', 2));
    Assert::eq(count($errors), 2);
    Assert::contains($errors[0], 'invalid worker_id');
    Assert::contains($errors[1], 'invalid worker_id');

    restore_error_handler();
    echo "DONE\n";
    $pool->shutdown();
});

$pool->on(Constant::EVENT_MESSAGE, function (Pool $pool, string $message) {
});

$pool->start();
?>
--EXPECT--
DONE
