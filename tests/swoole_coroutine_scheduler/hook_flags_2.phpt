--TEST--
swoole_coroutine_scheduler: hook_flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$hash = md5_file(TEST_IMAGE);

// 1
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function () use ($hash) {
    Assert::eq($hash, md5(file_get_contents(TEST_IMAGE)));
});
$sch->start();

Assert::eq($hash, md5(file_get_contents(TEST_IMAGE)));

// 2
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function () use ($hash) {
    Assert::eq($hash, md5(file_get_contents(TEST_IMAGE)));
});
$sch->start();

?>
--EXPECT--

