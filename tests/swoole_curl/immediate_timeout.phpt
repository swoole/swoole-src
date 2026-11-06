--TEST--
swoole_curl: start immediate work before yielding to the reactor
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $deferred = false;
    Event::defer(function () use (&$deferred) {
        $deferred = true;
    });

    $handle = curl_init('file://' . __FILE__);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);

    Assert::same(curl_exec($handle), file_get_contents(__FILE__));
    Assert::false($deferred);
});
?>
--EXPECT--
