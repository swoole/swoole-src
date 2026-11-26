--TEST--
swoole_runtime: accept timeout does not override the accepted stream timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
default_socket_timeout=2
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Runtime;
use SwooleTest\Assert;

Assert::setThrowException(true);
Runtime::enableCoroutine(SWOOLE_HOOK_TCP);
Coroutine\run(function () {
    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    Assert::true(is_resource($listener), $error);
    $address = 'tcp://' . stream_socket_get_name($listener, false);

    foreach ([2 => 'OK', 0 => ''] as $timeout => $expected) {
        stream_set_timeout($listener, $timeout);
        $client = stream_socket_client($address, $errno, $error, 2);
        Assert::true(is_resource($client), $error);
        $accepted = stream_socket_accept($listener, 0.03);
        Assert::true(is_resource($accepted));

        $written = new Channel(1);
        Coroutine::create(function () use ($client, $written) {
            Coroutine::sleep(0.15);
            $written->push(fwrite($client, 'OK'));
        });
        $data = fread($accepted, 2);
        $timedOut = stream_get_meta_data($accepted)['timed_out'];
        Assert::same($written->pop(2), 2);
        Assert::same($data, $expected, 'Accepted stream should use the listener timeout');
        Assert::false($timedOut);
        Assert::false(feof($accepted));
        fclose($accepted);
        fclose($client);
    }
    fclose($listener);
});
echo "DONE\n";
?>
--EXPECT--
DONE
