--TEST--
swoole_curl/multi: 6
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_API_PATH . '/curl_multi.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
run(function () {
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, 'https://' . TEST_DOMAIN_1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, static function (CurlHandle $curl, string $headerLine): int {
        throw new Exception('testh');
    });

    Assert::throws(static function () use ($ch): void {
        @curl_exec($ch);
    }, Exception::class, message: 'testh');

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, 'https://' . TEST_DOMAIN_2);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function (CurlHandle $curl, string $data): int {
        throw new Exception('testw');
    });

    Assert::throws(static function () use ($ch): void {
        curl_exec($ch);
    }, Exception::class, message: 'testw');

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, 'https://' . TEST_DOMAIN_1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_UPLOAD, 1);
    curl_setopt($ch, CURLOPT_INFILE, STDIN);
    curl_setopt($ch, CURLOPT_READFUNCTION, static function (CurlHandle $curl, mixed $fd, int $length): int {
        throw new Exception('testr');
    });

    Assert::throws(static function () use ($ch): void {
        curl_exec($ch);
    }, Exception::class, message: 'testr');

    echo "Done\n";
});
?>
--EXPECTF--
Done
