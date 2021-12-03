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
        $i = 1000000;
        while($i > 0) {
            $a = 10000 ^ 10000;
            $i--;
        }
        $execution_time = Swoole\Coroutine::getExecuteTime();
        $time = 2;
    	sleep($time);
    	Assert::assert($execution_time == Swoole\Coroutine::getExecuteTime());
    });

    go(function(){
        $time = 2;
    	Swoole\Runtime::enableCoroutine($flags = false);
    	sleep($time);
    	$execution_time = Swoole\Coroutine::getExecuteTime();
    	Swoole\Runtime::enableCoroutine($flags = SWOOLE_HOOK_ALL);
    	sleep($time);

    	go(function(){
    	    $time = 2;
    		Swoole\Runtime::enableCoroutine($flags = false);
    		sleep($time);
    		$execution_time = Swoole\Coroutine::getExecuteTime();
    		Swoole\Runtime::enableCoroutine($flags = SWOOLE_HOOK_ALL);
    		sleep($time);
    		Assert::assert($execution_time == Swoole\Coroutine::getExecuteTime());
    	});

    	Assert::assert($execution_time == Swoole\Coroutine::getExecuteTime());
    });

    Assert::assert(0 == Swoole\Coroutine::getExecuteTime());
    echo 'DONE';
});
?>
--EXPECT--
DONE
