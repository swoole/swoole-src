--TEST--
swoole_runtime/file_hook: protect fd across multiple coroutines - 4
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

run(function() {
	$data = 'aaaaaaa';
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, &$content1) {
		$waitGroup->add();
		file_get_contents(__FILE__);
    	$waitGroup->done();
    });

    go(function() use ($waitGroup, &$content2, $data) {
        $waitGroup->add();
        file_put_contents(__FILE__, $data, FILE_APPEND);
        file_get_contents(__FILE__);
        $waitGroup->done();
    });
	$waitGroup->wait();
});
?>
--EXPECTF--
