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

run(function() {
	$data = 'aaaaaaa';
	$content1 = '';
    $content2 = '';
	$waitGroup = new WaitGroup();
	go(function() use ($waitGroup, &$content1) {
		$waitGroup->add();
		$content1 = file_get_contents(__FILE__);
    	$waitGroup->done();
    });

    sleep(1);
    go(function() use ($waitGroup, &$content2, $data) {
        $waitGroup->add();
        file_put_contents(__FILE__, $data, FILE_APPEND);
        $content2 = file_get_contents(__FILE__);
        $waitGroup->done();
    });
	$waitGroup->wait();
	Assert::true($content1 . $data == $content2);
});
?>
--EXPECTF--
