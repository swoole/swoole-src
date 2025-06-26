--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 7
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;
use function Swoole\Coroutine\run;
use Swoole\Coroutine\WaitGroup;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
$fp = fopen(__FILE__, 'r');
run(function() use ($fp) {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, $fp) {
		$waitGroup->add();
		fgets($fp);
    	$waitGroup->done();
    });

    sleep(1);
    go(function() use ($waitGroup, $fp) {
        $waitGroup->add();
        fclose($fp);
        $waitGroup->done();
    });
	$waitGroup->wait();
	Assert::true($content1 . $data == $content2);
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: fd#%d has already been bound to another coroutine#%d, sharing the same fd across multiple coroutines is not allowed. in %s:%s
Stack trace:
#0 %s(%d): fclose(%s)
#1 %s
#2 {main}
  thrown in %s on line %d