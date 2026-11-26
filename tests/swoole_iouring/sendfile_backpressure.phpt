--TEST--
swoole_iouring: sendFile completes under socket backpressure
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_iouring();
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

Coroutine\run(static function () {
    $file = tmpfile();
    Assert::resource($file);
    $data = str_repeat('0123456789abcdef', 6144);
    Assert::same(fwrite($file, $data), strlen($data));
    fflush($file);
    $path = stream_get_meta_data($file)['uri'];

    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    $writer = Socket::import($pair[0]);
    $reader = Socket::import($pair[1]);
    Assert::true($writer->setOption(SOL_SOCKET, SO_SNDBUF, 4096));

    Coroutine::create(static function () use ($writer, $path) {
        Assert::true($writer->sendFile($path));
        Assert::same($writer->errCode, 0);
        $writer->close();
    });

    Coroutine::sleep(0.02);
    Assert::same($reader->recvAll(strlen($data), 2), $data);
    $reader->close();
    fclose($file);
});
echo "DONE\n";
?>
--EXPECT--
DONE
