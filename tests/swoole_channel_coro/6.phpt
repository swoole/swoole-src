--TEST--
swoole_channel_coro: push with sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$chan = new chan(1);

go(function () use ($chan) {
    echo "coro1 start\n";
    for ($i = 0; $i < 2; $i++) {
        $result = $chan->pop();
        var_dump($result);
    }
    echo 'pop over!'. PHP_EOL;
});

go(function () use ($chan){
    echo "coro2 start\n";
    $retval = [2,23,2];
    $chan->push($retval);
    echo "coro2 end\n";
});

go(function () use ($chan){
    echo "coro3 start\n";
    $eee = "hello word";
    $chan->push($eee);
    echo "coro3 end\n";
});

echo 'master end' . PHP_EOL;
swoole_event_wait();
?>
--EXPECT--
coro1 start
coro2 start
array(3) {
  [0]=>
  int(2)
  [1]=>
  int(23)
  [2]=>
  int(2)
}
coro2 end
coro3 start
string(10) "hello word"
pop over!
coro3 end
master end
