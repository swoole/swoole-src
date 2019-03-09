--TEST--
swoole_channel_coro: pop timeout 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$channel = new Swoole\Coroutine\Channel(1);
go(function () use ($channel) {
    $ret = $channel->push('foo', 0.001);
    assert($ret === true);
    $ret = $channel->push('foo', 0.001);
    assert($ret === true);
});
for ($n = MAX_REQUESTS; $n--;) {
    go(function () use ($channel) {
        $ret = $channel->push('foo', 0.001);
        assert($ret === false);
        assert($channel->errCode === SWOOLE_CHANNEL_TIMEOUT);
    });
}
go(function () use ($channel) {
    $ret = $channel->pop();
    assert($ret === 'foo');
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
