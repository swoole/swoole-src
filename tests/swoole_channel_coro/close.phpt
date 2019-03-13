--TEST--
swoole_channel_coro: coro channel stats
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $chan = new \chan(100);
    $a = [];
    $a['1'] = $chan;

    go(function () use (&$chan) {
        while (true) {
            $data = $chan->pop();
            if ($data == false) {
                break;
            }
            print("chan get data :$data\n");
        }
        print("chan exit\n");
    });

    $frame = '11';
    $chan->push($frame);
    co::sleep(0.2);
    print("chan close " . json_encode($chan->stats()) . "\n");
    $chan->close();
    co::sleep(0.2);
    print("chan END\n");
    unset($a['1']);
});

swoole_event::wait();
?>
--EXPECT--
chan get data :11
chan close {"consumer_num":1,"producer_num":0,"queue_num":0}
chan exit
chan END
