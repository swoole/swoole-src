--TEST--
swoole_redis_coro: stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip("unavailable, waiting for review");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

Co\run(function() {
    $redis = new Swoole\Coroutine\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $ret = $redis->del('mystream');

    // xGroupCreate
    $ret = $redis->xGroupCreate('mystream', 'group1', '0-0', true);
    Assert::assert($ret == '1');

    // xGroupCreateConsumer
    $ret = $redis->xGroupCreateConsumer('mystream', 'group1', 'consumer1');
    Assert::assert($ret == '1');
    $ret = $redis->xGroupCreateConsumer('mystream', 'group1', 'consumer2');
    Assert::assert($ret == '1');

    // xAdd
    $ret = $redis->xAdd('mystream', '0-1', ['field'=>'111'], ['nomkstream'=>true, 'maxlen'=>['~', 5], 'limit'=>5]);
    Assert::assert($ret == '0-1');
    $ret = $redis->xAdd('mystream', '0-2', ['field'=>'222'], ['nomkstream'=>false, 'minid'=>['~', '0-0'], 'limit'=>5]);
    Assert::assert($ret == '0-2');
    $ret = $redis->xAdd('mystream', '0-3', ['field'=>'333'], ['maxlen'=>['=', 5]]);
    Assert::assert($ret == '0-3');
    $ret = $redis->xAdd('mystream', '0-4', ['field'=>'444'], ['maxlen'=>5]);
    Assert::assert($ret, '0-4');
    $ret = $redis->xAdd('mystream', '0-5', ['field'=>'555']);
    Assert::assert($ret, '0-5');

    // xLen
    $ret = $redis->xLen('mystream');
    Assert::assert($ret == '5');

    // xRead
    $ret = $redis->xRead(['mystream'=>'0-3'], ['count'=>1, 'block'=>100]);
    Assert::assert($ret[0][1][0][0] == '0-4');

    // xRange
    $ret = $redis->xRange('mystream', '0-2', '0-3', 1);
    Assert::assert($ret[0][0] == '0-2');

    // xRevRange
    $ret = $redis->xRevRange('mystream', '+', '-', 1);
    Assert::assert($ret[0][0] == '0-5');

    // xReadGroup
    $ret = $redis->xReadGroup('group1', 'consumer1', ['mystream' => '>'], ['count'=>1, 'block'=>100, 'noack'=>true]);
    Assert::assert($ret[0][1][0][0] == '0-1');
    $ret = $redis->xReadGroup('group1', 'consumer1', ['mystream' => '>'], ['count'=>1, 'block'=>100, 'noack'=>false]);
    Assert::assert($ret[0][1][0][0] == '0-2');
    $ret = $redis->xReadGroup('group1', 'consumer1', ['mystream' => '>'], ['count'=>1]);
    Assert::assert($ret[0][1][0][0] == '0-3');

    // xPending
    $ret = $redis->xPending('mystream', 'group1', ['start'=>'-', 'end'=>'+', 'count'=>5]);
    Assert::assert(count($ret) == 2);
    Assert::assert($ret[0][0] == '0-2');
    Assert::assert($ret[1][0] == '0-3');

    // xAck
    $ret = $redis->xAck('mystream', 'group1', ['0-2']);
    Assert::assert($ret == '1');

    // xClaim
    $ret = $redis->xClaim('mystream', 'group1', 'consumer2', 0, ['0-3']);
    Assert::assert($ret[0][0] == '0-3');

    // xInfoConsumers
    $ret = $redis->xInfoConsumers('mystream', 'group1');
    Assert::assert($ret[1][3] == '1');

    // xAutoClaim
    $ret = $redis->xAutoClaim('mystream', 'group1', 'consumer1', 0, '0-3');
    Assert::assert($ret[1][0][0] == '0-3');

    // xInfoGroups
    $ret = $redis->xInfoGroups('mystream');
    Assert::assert($ret[0][1] == 'group1');
    Assert::assert($ret[0][5] == '1');

    // xInfoStream
    $ret = $redis->xInfoStream('mystream');
    Assert::assert($ret[1] == '5');

    // xDel
    $ret = $redis->xDel('mystream', '0-1', '0-2');
    Assert::assert($ret == '2');

    // xTrim
    $ret = $redis->xTrim('mystream', ['maxlen'=>1]);
    Assert::assert($ret == '2');
    $ret = $redis->xTrim('mystream', ['minid'=>['~', '0'], 'limit'=>1]);
    Assert::assert($ret == '0');

    // xGroupSetId
    $ret = $redis->xGroupSetId('mystream', 'group1', '0-1');
    Assert::assert($ret == '1');

    // xGroupDelConsumer
    $ret = $redis->xGroupDelConsumer('mystream', 'group1', 'consumer1');
    Assert::assert($ret == '1');

    // xGroupDestroy
    $ret = $redis->xGroupDestroy('mystream', 'group1');
    Assert::assert($ret == '1');

    $ret = $redis->del('mystream');

    echo "OK\n";
});
?>
--EXPECT--
OK
