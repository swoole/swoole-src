--TEST--
swoole_curl: curl_multi_exec() doesn't reach hard limit
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip('file protocol not supported', !in_array('file', curl_version()['protocols'], true));
skip_if_function_not_exist('proc_open');
skip_if_win();
skip_if_in_valgrind('requires the Zend memory limit');
skip('requires delayed OOM support', ini_get('memory_hard_limit_percent') === false);
?>
--FILE--
<?php
require __DIR__ . '/../include/unwind_exit.inc';

$file = tempnam(sys_get_temp_dir(), 'swoole-curl-oom-');
$chunk = str_repeat('x', 1024 * 1024);
for ($i = 0; $i < 16; $i++) {
    file_put_contents($file, $chunk, FILE_APPEND);
}

$result = run_unwind_exit_php(<<<'PHP'
ini_set('memory_limit', '8M');
register_shutdown_function(fn() => print("shutdown\n"));
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () use ($argv) {
    $mh = curl_multi_init();
    $ch = curl_init('file://' . $argv[2]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_BUFFERSIZE, 10 * 1024 * 1024);
    curl_multi_add_handle($mh, $ch);
    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh, 0.05);
    } while ($running);
    echo "no OOM\n";
});
PHP, [$file]);
unlink($file);

assert_unwind_exit($result, 255, "shutdown\n");
if (!str_contains($result[2], 'Allowed memory size of 8388608 bytes exhausted')) {
    throw new RuntimeException('Missing PHP OOM report: ' . $result[2]);
}
echo "DONE\n";
?>
--EXPECT--
DONE
