--TEST--
swoole_curl: curl_reset() clears CURLOPT_PRIVATE
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_PRIVATE, 'secret-marker');
    var_dump(curl_getinfo($ch, CURLINFO_PRIVATE));
    curl_reset($ch);
    var_dump(curl_getinfo($ch, CURLINFO_PRIVATE));
});
?>
--EXPECT--
string(13) "secret-marker"
bool(false)
