--TEST--
swoole_curl: suspend in callback
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
        Co::sleep(0.05);
        $header_count++;
        return strlen($strHeader);
    });

    echo "exec\n";
    $output = curl_exec($ch);
    Assert::contains($output, "baidu.com");
    if ($output === false) {
        echo "CURL Error:" . curl_error($ch);
    }
    echo "exec end\n";
    Assert::greaterThan($header_count, 1);
    curl_close($ch);
    echo "Close\n";
});

?>
--EXPECT--
exec
exec end
Close
