--TEST--
swoole_thread: recursive arguments fail before startup and allow a later valid construction
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$arguments = Thread::getArguments();
if ($arguments !== null) {
    $arguments[0]->add();
    Assert::same($arguments[1][0]['n'], 7);
    Assert::same($arguments[1][1]['n'], 7);
    return;
}

$started = new Thread\Atomic(0);
$recursive = [];
$recursive[] = &$recursive;
for ($i = 0; $i < 3; ++$i) {
    try {
        new Thread(__FILE__, $started, $recursive);
        Assert::true(false, 'Invalid arguments must not start a thread');
    } catch (ValueError $exception) {
        Assert::same($exception->getMessage(), 'Recursive arrays are not supported');
    }
    Assert::same($started->get(), 0);
}
$leaf = ['n' => 7];
$thread = new Thread(__FILE__, $started, [&$leaf, &$leaf]);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
Assert::same($started->get(), 1);
Assert::same(Thread::activeCount(), 1);
// Internal function entries serialize PHP arrays instead of converting them to shared containers.
$internal = new Thread('count', $recursive);
Assert::true($internal->join());
Assert::same($internal->getExitStatus(), 0);
if (PHP_VERSION_ID >= 80400) {
    Assert::same($internal->getResult(), 1);
}
echo "DONE\n";
?>
--EXPECT--
DONE
