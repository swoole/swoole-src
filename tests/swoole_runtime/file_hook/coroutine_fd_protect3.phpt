--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 3
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
$dir = opendir(__DIR__);
run(function() use ($dir) {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, $dir) {
		$waitGroup->add();
		while(($file = readdir($dir)) !== false) {
		}
		$waitGroup->done();
	});

	go(function() use ($waitGroup, $dir) {
		$waitGroup->add();
    	closedir($dir);
    	$waitGroup->done();
    });
	$waitGroup->wait();
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: fd#%d has already been bound to another coroutine#%d, sharing the same fd across multiple coroutines is not allowed. in %s:%s
Stack trace:
#0 %s(%d): closedir(%s)
#1 %s
#2 {main}
  thrown in %s on line %d
