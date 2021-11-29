--TEST--
swoole_coroutine: getExecuteTime
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

Swoole\Runtime::enableCoroutine($flags = SWOOLE_HOOK_ALL);
$i = 1000;

run(function()  use ($i) {
    go(function() use ($i) {
        $time = 1;
        sleep($time);
        while($i < 0) {
            $a = 1;
            $i--;
        }
        sleep($time);
        echo 'DONE';
        Assert::assert(Swoole\Coroutine::getExecuteTime() < $time * 2 * 1000);
     }
});
?>
--EXPECT--
DONE
