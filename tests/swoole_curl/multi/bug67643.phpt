--TEST--
swoole_curl/multi: Bug #67643 (curl_multi_getcontent returns '' when RETURNTRANSFER isn't set)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('curl')) print 'skip';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'file://'. __FILE__);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $mh = curl_multi_init();
    curl_multi_add_handle($mh, $ch);

    $running = 0;
    do {
        curl_multi_exec($mh, $running);
    } while($running > 0);

    $results = curl_multi_getcontent($ch);

    curl_multi_remove_handle($mh, $ch);
    curl_multi_close($mh);

    Assert::contains($results, 'Bug #67643');
    echo 'Done'.PHP_EOL;
});
?>
--EXPECT--
Done
