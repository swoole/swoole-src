--TEST--
swoole_http_server: construct cookie twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Cookie;

$cookie = new Cookie();

try {
    $cookie->__construct(false);
} catch (Error $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
Constructor of Swoole\Http\Cookie can only be called once
