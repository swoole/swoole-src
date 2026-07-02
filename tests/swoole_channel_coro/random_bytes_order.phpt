--TEST--
swoole_channel_coro: random bytes order
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;

const PRODUCER_N = 8;
const CONSUMER_N = 16;
const N = 10000;

$chan = new Coroutine\Channel(128);
$producerDone = new Coroutine\Channel(PRODUCER_N);
$consumerDone = new Coroutine\Channel(CONSUMER_N);
$expected = [];
$countMap = [];

for ($producerId = 0; $producerId < PRODUCER_N; $producerId++) {
    $countMap[$producerId] = intdiv(N, PRODUCER_N) + ($producerId < N % PRODUCER_N ? 1 : 0);
    for ($seq = 0; $seq < $countMap[$producerId]; $seq++) {
        $expected[$producerId][$seq] = random_bytes((($producerId + $seq) % 256) + 1);
    }
}

$received = [];
$lastSeq = array_fill(0, PRODUCER_N, -1);
$receivedN = 0;

for ($i = 0; $i < CONSUMER_N; $i++) {
    Coroutine::create(function () use ($chan, $consumerDone, &$expected, &$received, &$lastSeq, &$receivedN) {
        while (true) {
            $data = $chan->pop();
            if ($data === false) {
                break;
            }

            [$producerId, $seq, $payload] = $data;
            Assert::assert($seq > $lastSeq[$producerId]);
            Assert::same($payload, $expected[$producerId][$seq]);
            Assert::false(isset($received[$producerId][$seq]));

            $lastSeq[$producerId] = $seq;
            $received[$producerId][$seq] = true;
            $receivedN++;
        }

        Assert::true($consumerDone->push(true));
    });
}

for ($producerId = 0; $producerId < PRODUCER_N; $producerId++) {
    Coroutine::create(function () use ($chan, $producerDone, &$expected, $producerId) {
        foreach ($expected[$producerId] as $seq => $payload) {
            Assert::true($chan->push([$producerId, $seq, $payload]));
        }

        Assert::true($producerDone->push(true));
    });
}

Coroutine::create(function () use ($chan, $producerDone, $consumerDone, &$received, &$countMap, &$receivedN) {
    for ($i = 0; $i < PRODUCER_N; $i++) {
        Assert::true($producerDone->pop());
    }

    $chan->close();

    for ($i = 0; $i < CONSUMER_N; $i++) {
        Assert::true($consumerDone->pop());
    }

    Assert::eq($receivedN, N);
    for ($producerId = 0; $producerId < PRODUCER_N; $producerId++) {
        for ($seq = 0; $seq < $countMap[$producerId]; $seq++) {
            Assert::true(isset($received[$producerId][$seq]));
        }
    }

    echo "DONE\n";
});

Swoole\Event::wait();
?>
--EXPECT--
DONE
