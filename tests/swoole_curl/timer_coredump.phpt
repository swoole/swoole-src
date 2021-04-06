--TEST--
swoole_curl: timer coredump
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

function test()
{
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, 'https://httpbin.org/');
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_exec($curl);
    curl_close($curl);
}

run('test');
run('test');

echo "Done\n";
?>
--EXPECT--
Done
