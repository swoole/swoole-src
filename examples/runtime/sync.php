<?php
// This example writes a temporary file; remove it on exit to keep the tree clean.
register_shutdown_function(function () {
    foreach (glob(__DIR__ . '/data.txt') as $file) {
        @unlink($file);
    }
});
Swoole\Runtime::enableCoroutine();
go(function () {
    $fp = fopen(__DIR__ . '/data.txt', 'w+');
    fwrite($fp, str_repeat('A', 8192));
    fflush($fp);
    fclose($fp);
});
