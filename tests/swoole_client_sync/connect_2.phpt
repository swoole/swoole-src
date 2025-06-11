--TEST--
swoole_client_sync: connect 1 - 2
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

killself_in_syncmode(1000, SIGTERM);

$cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = $cli->connect(TEST_DOMAIN_3, 443);
Assert::assert($r);
$cli->close();
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
