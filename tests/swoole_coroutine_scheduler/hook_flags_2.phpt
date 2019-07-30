--TEST--
swoole_coroutine_scheduler: hook_flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const URL = "http://www.xinhuanet.com/";
// 1
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function () {
    Assert::contains(file_get_contents(URL), '新华网');
});
$sch->start();

Assert::contains(file_get_contents(URL), '新华网');

// 2
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function ()  {
    Assert::contains(file_get_contents(URL), '新华网');
});
$sch->start();

?>
--EXPECT--
