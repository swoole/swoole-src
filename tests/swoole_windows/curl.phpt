--TEST--
swoole_windows: coroutine curl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!extension_loaded('curl')) {
    die('skip curl extension not loaded');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $url = 'https://' . TEST_DOMAIN_3 . '/';

    $jobs = [];
    for ($i = 0; $i < 2; $i++) {
        $jobs[] = go(function () use ($url) {
            $ch = curl_init();
            Assert::isInstanceOf($ch, Swoole\Curl\Handler::class);
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);

            $body = curl_exec($ch);
            Assert::assert(is_string($body));
            Assert::notEmpty($body);
            Assert::same(curl_error($ch), '');
            Assert::same(curl_getinfo($ch, CURLINFO_HTTP_CODE) > 0, true);
            curl_close($ch);
        });
    }

    Co::join($jobs);
});

echo "DONE\n";
?>
--EXPECT--
DONE
