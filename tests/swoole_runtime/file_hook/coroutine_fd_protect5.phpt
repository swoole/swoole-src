--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 5
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

$fd = fopen(__FILE__, 'ar+');
run(function() use ($fd) {
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, $fd) {
		$waitGroup->add();
		for ($i = 0; $i < 100; $i++) {
			fwrite($fd, 'aaaaaaaaaa');
		}
    	fclose($fd);
    	$waitGroup->done();
    });
	$waitGroup->wait();
});
?>
--EXPECTF--
