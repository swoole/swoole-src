--TEST--
swoole_coroutine: set timeout
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Runtime;
use Swoole\Coroutine\WaitGroup;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\TimeoutException;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
run(function() {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup) {
		$waitGroup->add();
    	Assert::true(Coroutine::setTimeLimit(2.5));
    	sleep(1);
    	$waitGroup->done();
    });

    go(function() use ($waitGroup) {
    	try {
    	    $waitGroup->add();
    		Assert::true(Coroutine::setTimeLimit(1.5));
            sleep(2);
    	} catch (TimeoutException $e) {
    		echo "timeout";
    	} finally {
    	    $waitGroup->done();
    	}
    });
    $waitGroup->wait();
});
?>
--EXPECT--
timeout
