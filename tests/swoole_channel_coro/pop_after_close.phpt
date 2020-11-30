--TEST--
swoole_channel_coro: pop after close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;

use function Swoole\Coroutine\run;

run(function () {
    $chan = new Channel();

    go(function () use ($chan) {
        for ($i = 1; $i <= 3; $i++) {
            if ($chan->push($i)) {
                echo "push ok\n";
            }
        }
        $chan->close();
    });

    go(function () use ($chan) {
        while (true) {
            $data = $chan->pop();
            var_dump($data);
            if (!$data) {
                break;
            }
        }
    });
});
?>
--EXPECT--
push ok
push ok
int(1)
push ok
int(2)
int(3)
bool(false)
