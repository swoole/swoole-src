--TEST--
swoole_coroutine: getExecuteTime
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_coroutine_get_execute_time();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function(){
    $i = 1000000;
    while($i > 0) {
        $a = 9999 ^ 10000;
        $i--;
    }
    $execution_time = Swoole\Coroutine::getExecuteTime();

    go(function(){
        $time = 2;
    	Swoole\Runtime::enableCoroutine($flags = false);
    	sleep($time);
    	$execution_time = Swoole\Coroutine::getExecuteTime();
    	Swoole\Runtime::enableCoroutine($flags = SWOOLE_HOOK_ALL);
    	sleep($time);
    	Assert::assert(Swoole\Coroutine::getExecuteTime() - $execution_time < 1000);
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
    		Assert::assert(Swoole\Coroutine::getExecuteTime() - $execution_time < 1000);
    	});

    	Assert::assert(Swoole\Coroutine::getExecuteTime() - $execution_time < 1000);
    });

    Assert::assert(Swoole\Coroutine::getExecuteTime() - $execution_time < 1000);
    echo 'DONE';
});
?>
--EXPECT--
DONE
