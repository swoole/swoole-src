--TEST--
swoole_channel_coro: push yield=false
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function(){
    $chan = new chan();
    go(function() use ($chan) {
        while (false !== ($value = $chan->pop())) {
            var_dump($value);
        }
    });
    for($i = 0; $i < 3; ++$i) {
        $chan->push($i, -1, false);
    }
    $chan->close();
    var_dump('complete');
});

?>
--EXPECTF--
int(0)
string(8) "complete"
int(1)
int(2)
