--TEST--
swoole_websocket_server: websocket frame pack/unpack
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

error_reporting(error_reporting() & ~(E_NOTICE));

use Swoole\WebSocket\Frame as f;
use Swoole\WebSocket\CloseFrame as cf;

for ($i = 1000; $i--;) {
    // generate some rand frames
    $opcode = mt_rand(WEBSOCKET_OPCODE_CONTINUATION, WEBSOCKET_OPCODE_PONG);
    $data = base64_encode(openssl_random_pseudo_bytes(mt_rand(0, 128000))) . 'EOL';
    if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
        $code = mt_rand(0, 5000);
        $data = substr($data, -mt_rand(3, 125), 125);
    }
    $finish = !!mt_rand(0, 1);
    $mask = !!mt_rand(0, 1);

    // pack them
    if (mt_rand(0, 1) || $opcode === WEBSOCKET_OPCODE_CLOSE) {
        if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
            $frame = new cf;
            $frame->code = $code;
            $frame->reason = $data;
        } else {
            $frame = new f;
            $frame->data = $data;
        }
        $frame->opcode = $opcode;
        $frame->finish = $finish;
        $frame->mask = $mask;
        if (!mt_rand(0, 4)) {
            unset($frame->data);
            unset($frame->reason);
            $data = '';
        }
        if (mt_rand(0, 1)) {
            $packed = (string)$frame;
        } else {
            $packed = f::pack($frame);
        }
    } else {
        $packed = f::pack($data, $opcode, $finish, $mask);
    }

    // unpack
    $unpacked = f::unpack($packed);

    // verify
    if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
        Assert::eq($unpacked->code, $code);
        Assert::eq($unpacked->reason, $data);
        Assert::true($unpacked->finish);
    } else {
        Assert::eq($unpacked->data, $data);
        Assert::eq($unpacked->opcode, $opcode);
        Assert::eq($unpacked->finish, $finish);
    }
}
?>
--EXPECT--
