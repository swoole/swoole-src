--TEST--
swoole_runtime/unsafe: dns
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;

$fn_list = ['exec', 'shell_exec', 'system', 'passthru'];

run(function () use ($fn_list)  {
    $running = true;
    $count = 0;
    $cid = Co\go(function () use (&$count, &$running) {
        while ($running) {
            $count++;
            sleep(1);
        }
    });
    foreach ($fn_list as $fn) {
        $fn("ping -4 www.gov.cn -c 3");
    }
    $running = false;
    Co::join([$cid]);
    Assert::greaterThanEq($count, 9);
});
?>
--EXPECTF--
