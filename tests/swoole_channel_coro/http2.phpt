--TEST--
swoole_channel_coro: http2 mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

for ($c = MAX_CONCURRENCY; $c--;) {
    go(function () {
        for ($n = MAX_REQUESTS; $n--;) {
            $recv = new Chan;
            $send = new Chan;
            $rand = get_safe_random(mt_rand(1, 1024));
            go(function () use ($recv) {
                co::sleep(0.001);
                $recv->push(new stdClass()); // response
            });
            go(function () use ($send, $rand) {
                $data = $send->pop();
                if (Assert::assert($data === $rand)) {
                    co::sleep(0.001);
                    $send->push(true); // send ok
                }
            });
            $ret = $send->push($rand);
            Assert::assert($ret);
            $response = $recv->pop();
            Assert::isInstanceOf($response, stdClass::class);
        }
    });
}

?>
--EXPECT--
