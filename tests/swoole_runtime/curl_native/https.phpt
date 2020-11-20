--TEST--
swoole_runtime/curl_native: https
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

const N = 8;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL_NATIVE);
$s = microtime(true);
run(function () {
    $n = N;
    while($n--) {
        go(function() {
            $ch = curl_init();
            $code = uniqid('swoole_');
            $url = "https://www.baidu.com/?code=".urlencode($code);

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
                return strlen($strHeader);
            });

            $output = curl_exec($ch);
            Assert::notEmpty($output);
            Assert::greaterThan(strlen($output), 10000);
            if ($output === false) {
                echo "CURL Error:" . curl_error($ch);
            }
            curl_close($ch);
        });
    }
});
echo "Done\n";
?>
--EXPECT--
Done
