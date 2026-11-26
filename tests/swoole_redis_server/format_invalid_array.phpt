--TEST--
swoole_redis_server: format rejects invalid SET and MAP values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

foreach ([Server::SET, Server::MAP] as $type) {
    foreach ([null, false, 42, 'value'] as $value) {
        try {
            Server::format($type, $value);
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
            Assert::same($exception->getMessage(), 'the second parameter should be an array');
            continue;
        }

        throw new RuntimeException('expected an exception for a non-array value');
    }
}

Assert::same(Server::format(Server::SET, [42]), "*1\r\n:42\r\n");
Assert::same(Server::format(Server::MAP, ['value' => 42]), "*2\r\n\$5\r\nvalue\r\n:42\r\n");
echo "DONE\n";
?>
--EXPECT--
DONE
