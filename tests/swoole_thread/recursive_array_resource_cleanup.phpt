--TEST--
swoole_thread: rejecting recursive arrays releases duplicated stream descriptors
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
Assert::notSame($listener, false);
$source = ['stream' => $listener, 'text' => str_repeat('x', 4096)];
$source['self'] = &$source;
$before = count(scandir('/proc/self/fd'));
for ($i = 0; $i < 32; ++$i) {
    try {
        new Swoole\Thread\Map($source);
        Assert::true(false, 'Recursive input must fail after duplicating the stream');
    } catch (ValueError $exception) {
        Assert::same($exception->getMessage(), 'Recursive arrays are not supported');
    }
}
Assert::same(count(scandir('/proc/self/fd')), $before);
Assert::true(is_resource($listener));
unset($source['self']);
$copy = new Swoole\Thread\Map($source);
Assert::true(is_resource($copy['stream']));
unset($copy);
fclose($listener);
echo "DONE\n";
?>
--EXPECT--
DONE
