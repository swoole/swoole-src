<?php
// One curl request inside a coroutine (native curl hook).
// Start examples/http/hello.php first, then run this.
// Run: php examples/curl/single_request.php
use function Swoole\Coroutine\run;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $ch = curl_init('http://127.0.0.1:9501/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    if ($body === false) {
        echo 'start examples/http/hello.php first' . PHP_EOL;
        return;
    }
    echo 'body: ', trim($body), PHP_EOL;
    curl_close($ch);
});
