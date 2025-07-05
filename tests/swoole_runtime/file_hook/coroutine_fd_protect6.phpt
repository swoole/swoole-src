--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 6
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

ini_set('memory_limit', -1);
file_put_contents(__FILE__, random_bytes(1024 * 1024 * 100));
$fd = fopen(__FILE__, 'r+');
run(function() use ($fd) {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, $fd) {
		$waitGroup->add();
		fread($fd, filesize(__FILE__));
		$waitGroup->done();
	});

	go(function() use ($waitGroup, $fd) {
		$waitGroup->add();
    	fread($fd, filesize(__FILE__));
    	$waitGroup->done();
    });
	$waitGroup->wait();
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: fd#%d has already been bound to another coroutine#%d, sharing the same fd across multiple coroutines is not allowed. in %s:%s
Stack trace:
#0 %s(%d): fread(%s)
#1 %s
#2 {main}
  thrown in %s on line %d
