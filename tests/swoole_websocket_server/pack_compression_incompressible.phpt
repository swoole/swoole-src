--TEST--
swoole_websocket_server: compressed binary frames survive output buffer exhaustion
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
skip_if_extension_not_exist('zlib');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;

$payloads = require __DIR__ . '/../include/websocket_compression_fixture.inc';
foreach ($payloads as $data) {
    foreach ([0, SWOOLE_WEBSOCKET_FLAG_MASK] as $maskFlag) {
        $packed = Frame::pack($data, WEBSOCKET_OPCODE_BINARY,
            SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS | $maskFlag);
        Assert::same(ord($packed[0]), $data === '' ? 0x82 : 0xC2);
        Assert::same((bool) (ord($packed[1]) & 0x80), (bool) $maskFlag);

        $length = ord($packed[1]) & 0x7F;
        $offset = 2;
        if ($length === 126) {
            $length = unpack('n', substr($packed, $offset, 2))[1];
            $offset += 2;
        } elseif ($length === 127) {
            $parts = unpack('Nhigh/Nlow', substr($packed, $offset, 8));
            Assert::same($parts['high'], 0);
            $length = $parts['low'];
            $offset += 8;
        }
        $mask = $maskFlag ? substr($packed, $offset, 4) : '';
        $offset += $maskFlag ? 4 : 0;
        Assert::same(strlen($packed), $offset + $length);
        $compressed = substr($packed, $offset);
        if ($maskFlag) {
            $compressed ^= str_repeat($mask, intdiv($length + 3, 4));
        }

        // Use PHP's zlib directly so the encoder and decoder cannot hide the same bug.
        if ($data === '') {
            Assert::same($compressed, '');
        } else {
            $context = inflate_init(ZLIB_ENCODING_RAW);
            Assert::same(inflate_add($context, $compressed . "\x00\x00\xff\xff", ZLIB_SYNC_FLUSH), $data);
            Assert::same(inflate_get_read_len($context), strlen($compressed) + 4);
        }
    }
}

echo "DONE\n";
?>
--EXPECT--
DONE
