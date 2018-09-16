--TEST--
swoole_websocket_server: websocket frame pack/unpack
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use swoole_websocket_frame as f;

for ($i = 10000; $i--;) {
    // generate some rand frames
    $opcode = mt_rand(WEBSOCKET_OPCODE_CONTINUATION, WEBSOCKET_OPCODE_PONG);
    $data = base64_encode(openssl_random_pseudo_bytes(mt_rand(0, 12800))) . 'EOL';
    if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
        $code = mt_rand(0, 5000);
        $data = substr($data, -mt_rand(3, 125), 125);
    }
    $finish = !!mt_rand(0, 1);
    $mask = !!mt_rand(0, 1);

    // pack them
    if (mt_rand(0, 1) || $opcode === WEBSOCKET_OPCODE_CLOSE) {
        if ($opcode === WEBSOCKET_OPCODE_CLOSE) {
            $frame = new swoole_websocket_close_frame;
            $frame->code = $code;
            $frame->reason = $data;
        } else {
            $frame = new swoole_websocket_frame;
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
        assert($unpacked->code === $code);
        assert($unpacked->reason === $data);
        assert($unpacked->finish === true);
    } else {
        assert($unpacked->data === $data);
        assert($unpacked->opcode === $opcode);
        assert($unpacked->finish === $finish);
    }
}
?>
--EXPECT--