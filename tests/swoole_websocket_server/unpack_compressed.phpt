--TEST--
swoole_websocket_server: unpack compressed frame with and without mask
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$payload = str_repeat('swoole-websocket-frame:', 20) . 'x';
$cases = [
    SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_MASK | SWOOLE_WEBSOCKET_FLAG_COMPRESS,
    SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS,
];

foreach ($cases as $flags) {
    $packed = Frame::pack($payload, WEBSOCKET_OPCODE_TEXT, $flags);
    $original = $packed;
    $expectedFlags = $flags | SWOOLE_WEBSOCKET_FLAG_RSV1;

    Assert::same(ord($packed[0]) & 0x40, 0x40);
    Assert::same(ord($packed[1]) & 0x80, ($flags & SWOOLE_WEBSOCKET_FLAG_MASK) ? 0x80 : 0);

    foreach ([Frame::class, Server::class] as $class) {
        $frame = $class::unpack($packed);
        if (!Assert::isInstanceOf($frame, Frame::class)) {
            continue;
        }
        Assert::same($frame->data, $payload);
        Assert::same($frame->opcode, WEBSOCKET_OPCODE_TEXT);
        Assert::true($frame->finish);
        Assert::same($frame->flags, $expectedFlags);
        Assert::same($packed, $original);
    }
}

echo "DONE\n";
?>
--EXPECT--
DONE
