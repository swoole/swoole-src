--TEST--
swoole_runtime/curl_native: suspend in callback
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;
$pm = new SwooleTest\ProcessManager;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($pm) {
    $ch = curl_init();
    $code = uniqid('swoole_');
    $url = "http://www.baidu.com/?code=".urlencode($code);

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);

    $header_count = 0;
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) use (&$header_count) {
        Assert::eq(curl_getinfo($ch, CURLINFO_HTTP_CODE), 200);
        Assert::eq(md5_file(__FILE__), md5(file_get_contents(__FILE__)));
        $header_count++;
        Co::sleep(0.1);
        return strlen($strHeader);
    });

    $output = curl_exec($ch);
    Assert::eq($output, "Hello World\n".$code);
    if ($output === false) {
        echo "CURL Error:" . curl_error($ch);
    }
    Assert::greaterThan($header_count, 1);
    curl_close($ch);
    echo "Close\n";
});

?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: API must be called in the coroutine in %s:%d
Stack trace:
#0 %s(%d): Swoole\Coroutine::sleep(0.1)
#1 [internal function]: {closure}(Resource id #%d, 'HTTP/1.1 200 OK...')
#2 @swoole-src/library/alias_ns.php(%d): Swoole\Coroutine\Scheduler->start()
#3 %s(%d): Swoole\Coroutine\run(Object(Closure))
#4 {main}
  thrown in %s on line %d
