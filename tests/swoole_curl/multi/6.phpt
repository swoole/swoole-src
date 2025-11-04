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

    curl_setopt($ch, CURLOPT_URL, TEST_DOMAIN_1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, static function (CurlHandle $curl, string $headerLine): int {
        debug_print_backtrace();
        throw new Exception('testh');
    });

    Assert::throws(static function () use ($ch): void {
        curl_exec($ch);
    }, Exception::class, message: 'testh');

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, TEST_DOMAIN_2);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function (CurlHandle $curl, string $data): int {
        debug_print_backtrace();
        throw new Exception('testw');
    });

    Assert::throws(static function () use ($ch): void {
        curl_exec($ch);
    }, Exception::class, message: 'testw');

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, TEST_DOMAIN_1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_UPLOAD, 1);
    curl_setopt($ch, CURLOPT_INFILE, STDIN);
    curl_setopt($ch, CURLOPT_READFUNCTION, static function (CurlHandle $curl, mixed $fd, int $length): int {
        debug_print_backtrace();
        throw new Exception('testr');
    });

    Assert::throws(static function () use ($ch): void {
        curl_exec($ch);
    }, Exception::class, message: 'testr');

    echo "Done\n";
});
?>
--EXPECTF--
#0 [internal function]: {closure:{closure:%s:%d}:%d}(Object(CurlHandle), 'HTTP/1.1 200 OK...')
#1 %s(%d): curl_exec(Object(CurlHandle))
#2 %s/Assert.php(%d): {closure:{closure:%s:%d}:%d}()
#3 %s(%d): SwooleTest\Assert::throws(Object(Closure), 'Exception', 'testh')
#4 [internal function]: {closure:%s:%d}()
#0 [internal function]: {closure:{closure:%s:%d}:%d}(Object(CurlHandle), '<html>\r\n<head><...')
#1 %s(%d): curl_exec(Object(CurlHandle))
#2 %s/Assert.php(%d): {closure:{closure:%s:%d}:%d}()
#3 %s(%d): SwooleTest\Assert::throws(Object(Closure), 'Exception', 'testw')
#4 [internal function]: {closure:%s:%d}()
#0 [internal function]: {closure:{closure:%s:%d}:%d}(Object(CurlHandle), Resource id #%d, %d)
#1 %s(%d): curl_exec(Object(CurlHandle))
#2 %s/Assert.php(%d): {closure:{closure:%s:%d}:%d}()
#3 %s(%d): SwooleTest\Assert::throws(Object(Closure), 'Exception', 'testr')
#4 [internal function]: {closure:%s:%d}()
Done
