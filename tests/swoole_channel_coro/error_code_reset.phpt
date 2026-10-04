--TEST--
swoole_channel_coro: error code is reset after a successful operation
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;

use function Swoole\Coroutine\run;

run(function () {
    $chan = new Channel(1);
    Assert::false($chan->pop(0.001));
    Assert::same($chan->errCode, SWOOLE_CHANNEL_TIMEOUT);
    Assert::true($chan->push('foo'));
    Assert::same($chan->errCode, SWOOLE_CHANNEL_OK);

    Assert::false($chan->push('bar', 0.001));
    Assert::same($chan->errCode, SWOOLE_CHANNEL_TIMEOUT);
    Assert::same($chan->pop(), 'foo');
    Assert::same($chan->errCode, SWOOLE_CHANNEL_OK);
});
echo "DONE\n";
?>
--EXPECT--
DONE
