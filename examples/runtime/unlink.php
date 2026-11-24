<?php
// File operations inside a coroutine are hooked to the event loop.
// Run: php examples/runtime/unlink.php
use function Swoole\Coroutine\run;

Swoole\Runtime::enableCoroutine();

$tmp = __DIR__ . '/data.txt';
file_put_contents($tmp, 'hello');

run(function () use ($tmp) {
    var_dump(unlink($tmp));
});

// Keep the tree clean even if the example stops before the unlink() runs.
register_shutdown_function(function () use ($tmp) {
    if (is_file($tmp)) {
        @unlink($tmp);
    }
});
