--TEST--
swoole_curl: https
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

const N = 8;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
$s = microtime(true);
run(function () {
    $n = N;
    while($n--) {
        go(function() {
            $ch = curl_init();
            $code = uniqid('swoole_');
            if (IS_IN_TRAVIS) {
                $domain = 'www.google.com';
            } else {
                $domain = 'www.baidu.com';
            }
            $url = "https://{$domain}/?code=".urlencode($code);

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT , 2);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
                return strlen($strHeader);
            });

            $output = curl_exec($ch);
            if ($output === false) {
                echo "CURL Error:" . curl_error($ch);
            }
            Assert::notEmpty($output);
            Assert::greaterThan(strlen($output), 10000);
            curl_close($ch);
        });
    }
});
echo "Done\n";
?>
--EXPECT--
Done
