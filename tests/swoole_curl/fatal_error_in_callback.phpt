--TEST--
swoole_curl: error
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
$s = microtime(true);
run(function () {
    $ch = curl_init();
    $code = uniqid('swoole_');
    if (IS_IN_CI) {
        $domain = 'www.google.com';
    } else {
        $domain = 'www.baidu.com';
    }
    $url = "https://{$domain}/?code=" . urlencode($code);

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $strHeader) {
        trigger_error("test", E_USER_ERROR);
        return strlen($strHeader);
    });

    register_shutdown_function(function () use ($ch) {
        try {
            curl_close($ch);
        } catch (throwable $e) {
            trigger_error($e->getMessage(), E_USER_WARNING);
        }

    });

    curl_exec($ch);
    echo "Exec\n";
    curl_close($ch);
});
echo "Done\n";
?>
--EXPECTF--
Fatal error: test in %s on line %d

Warning: curl_close(): Attempt to close cURL handle from a callback in %s on line %d
--EXPECTF_85--
Fatal error: test in %s on line %d
Stack trace:
#0 %s(%d): trigger_error('test', %d)
#1 [internal function]: {closure:{closure:%s:%d}:%d}(Object(CurlHandle), '<html>\r\n<head>\r...')
#2 %s(%d): curl_exec(Object(CurlHandle))
#3 [internal function]: {closure:%s:%d}()
#4 {main}

Warning: curl_close(): Attempt to close cURL handle from a callback in %s on line %d
