--TEST--
swoole_runtime/unsafe: dns
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function () {
    $fn_list = ['exec', 'shell_exec', 'system', 'passthru'];
    Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);
    run(function () use ($fn_list)  {
        $running = true;
        $count = 0;
        $cid = Co\go(function () use (&$count, &$running)  {
            while ($running) {
                $count++;
                sleep(1);
            }
        });
        foreach ($fn_list as $fn) {
            $rs = $fn("ping -4 www.gov.cn -c 3");var_dump($rs);
        }
        $running = false;
        Co::join([$cid]);
        Assert::greaterThanEq($count, 9);
    });
});

Assert::eq(substr_count($pm->getChildOutput(), 'ping statistics'), 3);
Assert::eq($pm->getChildExitStatus(), 0);
?>
--EXPECTF--
