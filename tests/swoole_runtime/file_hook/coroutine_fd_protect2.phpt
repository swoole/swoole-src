--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 2
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
if (defined('SWOOLE_IOURING_SQPOLL')) {
	$setting = [
        'iouring_workers' => 32,
        'iouring_entries' => 30000,
        'iouring_flag' => SWOOLE_IOURING_SQPOLL,
    ];
    swoole_async_set($setting);
}

$fd = fopen(__FILE__, 'r+');
run(function() use ($fd) {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, $fd) {
		$waitGroup->add();
		$content = fread($fd, filesize(__FILE__));
		Assert::True(strlen($content) == filesize(__FILE__));
		$waitGroup->done();
	});

	sleep(1);
	go(function() use ($waitGroup, $fd) {
		$waitGroup->add();
    	fwrite($fd, 'aaaaaaaaaa');
    	$waitGroup->done();
    });
	$waitGroup->wait();
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: fd#%d has already been bound to another coroutine#%d, sharing the same fd across multiple coroutines is not allowed. in %s:%s
Stack trace:
#0 %s(%d): fwrite(%s)
#1 %s
#2 {main}
  thrown in %s on line %d