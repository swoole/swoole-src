--TEST--
swoole_coroutine: getExecuteTime
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function(){
    go(function(){
        $time = 1;
        Swoole\Runtime::enableCoroutine(false);
        sleep($time);
        Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
        sleep($time);
        echo 'DONE';
        Assert::assert(round(Swoole\Coroutine::getExecuteTime() / ($time * 1000)) == 1);
     });
});
?>
--EXPECT--
DONE
