--TEST--
swoole_websocket_server: websocket frame pack/unpack
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

error_reporting(error_reporting() & ~(E_NOTICE));

use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;

for ($i = 1000; $i--;) {
    // generate some rand frames
    $opcode = mt_rand(WEBSOCKET_OPCODE_CONTINUATION, WEBSOCKET_OPCODE_PONG);
    $data = base64_encode(get_safe_random(mt_rand(0, 128000))) . 'EOL';
    if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
        $code = mt_rand(0, 5000);
        $data = substr($data, -mt_rand(3, 125), 125);
    }
    $finish = !!mt_rand(0, 1);

    // pack them
    if (mt_rand(0, 1) || $opcode === WEBSOCKET_OPCODE_CLOSE) {
        if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
            $frame = new CloseFrame;
            $frame->code = $code;
            $frame->reason = $data;
        } else {
            $frame = new Frame;
            $frame->data = $data;
        }
        $frame->opcode = $opcode;
        $frame->finish = $finish;
        if (!mt_rand(0, 4)) {
            unset($frame->data);
            unset($frame->reason);
            $data = '';
        }
        if (mt_rand(0, 1)) {
            $packed = (string)$frame;
        } else {
            $packed = Frame::pack($frame);
        }
    } else {
        $packed = Frame::pack($data, $opcode, $finish);
    }

    // unpack
    $unpacked = Frame::unpack($packed);

    // verify
    if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
        Assert::same($unpacked->code, $code);
        Assert::same($unpacked->reason, $data);
        Assert::true($unpacked->finish);
    } else {
        Assert::same($unpacked->data, $data);
        Assert::same($unpacked->opcode, $opcode);
        Assert::same($unpacked->finish, $finish);
    }
}
?>
--EXPECT--
