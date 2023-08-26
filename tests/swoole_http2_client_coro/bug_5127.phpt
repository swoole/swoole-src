--TEST--
swoole_http2_client_coro: Github #5127 When use swoole in php 8.2，Swoole\Http2\Request may throw ErrorException：Creation of dynamic property $usePipelineRead
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$request = new Swoole\Http2\Request();
$request->usePipelineRead = true;
echo 'DONE';
?>
--EXPECT--
DONE
