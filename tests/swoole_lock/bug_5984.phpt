--TEST--
swoole_lock: Github Bug #5984
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as Co;
Co::set(['hook_flags' => SWOOLE_HOOK_ALL & ~SWOOLE_HOOK_CURL]);
$fileEx = '/tmp/test_ex.txt';
file_put_contents($fileEx, '0');

$lockEx = file_get_contents($fileEx);
Co\run(function () use ($fileEx) {
	for ($i = 0; $i < 50; $i++) {
		go(function () use ($i, $fileEx) {
			$fp = fopen($fileEx, 'r+');
			flock($fp, LOCK_EX);
			$val = (int) file_get_contents($fileEx);
			usleep(100);
			file_put_contents($fileEx, (string) ($val + 1));
			flock($fp, LOCK_UN);
			fclose($fp);
		});
	}
});

$val = (int) file_get_contents($fileEx);
echo $val === 50 ? "✓ 通过 (计数=$val)\n" : "✗ 失败 (计数=$val, 预期50)\n";
?>
--EXPECT--
✓ 通过 (计数=50)
