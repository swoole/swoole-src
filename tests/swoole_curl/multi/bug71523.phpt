--TEST--
swoole_curl/multi: Bug #71523 (Copied handle with new option CURLOPT_HTTPHEADER crashes while curl_multi_exec)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded("curl")) {
    exit("skip curl extension not loaded");
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $base = curl_init('http://www.baidu.com/');
    curl_setopt($base, CURLOPT_RETURNTRANSFER, true);
    $mh = curl_multi_init();

    for ($i = 0; $i < 2; ++$i) {
        $ch = curl_copy_handle($base);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Foo: Bar']);
        curl_multi_add_handle($mh, $ch);
    }

    do {
        curl_multi_exec($mh, $active);
    } while ($active);
});
?>
okey
--EXPECT--
okey
