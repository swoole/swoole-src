--TEST--
swoole_server: reject message queue keys outside key_t
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip('64-bit only', PHP_INT_SIZE < 8);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_BASE);
Assert::true($server->set(['message_queue_key' => 0xffffffff]));
try {
    $server->set(['message_queue_key' => 1 << 32]);
    Assert::true(false, 'out-of-range message_queue_key must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::same($exception->getMessage(), 'message_queue_key is out of range');
}
Assert::same($server->setting['message_queue_key'], 0xffffffff);
echo "DONE\n";
?>
--EXPECT--
DONE
