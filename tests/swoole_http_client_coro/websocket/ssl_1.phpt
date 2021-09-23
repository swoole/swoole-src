--TEST--
swoole_http_client_coro/websocket: ssl recv
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip("unavailable, waiting for review");
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Co\run(function ()  {
    $cli = new Co\http\Client('echo.websocket.org', 443, true);
    $ret = $cli->upgrade('/');

    if (!$ret) {
        echo "ERROR\n";
        return;
    }
    $n = 16;
    while ($n--) {
        $data = base64_encode(random_bytes(rand(1, 16*1024)));
        $cli->push($data);
        $frame = $cli->recv();
        Assert::true(is_object($frame));
        Assert::eq($frame->data, $data);
    }
});
?>
--EXPECT--
