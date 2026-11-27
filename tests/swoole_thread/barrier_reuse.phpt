--TEST--
swoole_thread: barrier reuse publishes every participant's writes across generations
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\ArrayList;
use Swoole\Thread\Barrier;

function waitRounds(Barrier $barrier, ArrayList $values, int $id, int $count): void
{
    for ($round = 1; $round <= 32; ++$round) {
        // Rotate the late participant rather than relying on any particular thread startup order.
        if ($round % $count === $id) {
            usleep(1000);
        }
        $values[$id] = $round;
        $barrier->wait();
        for ($other = 0; $other < $count; ++$other) {
            Assert::same($values[$other], $round);
        }
        // Protect the current values from the following round's writes.
        $barrier->wait();
    }
}

$tm = new SwooleTest\ThreadManager();
$tm->parentFunc = function () {
    foreach ([2, 4] as $count) {
        $barrier = new Barrier($count);
        $values = new ArrayList(array_fill(0, $count, 0));
        $threads = [];
        for ($id = 1; $id < $count; ++$id) {
            $threads[] = new Thread(__FILE__, $barrier, $values, $id, $count);
        }
        waitRounds($barrier, $values, 0, $count);
        foreach ($threads as $thread) {
            Assert::true($thread->join());
        }
    }
    echo "DONE\n";
};
$tm->childFunc = function (Barrier $barrier, ArrayList $values, int $id, int $count) {
    waitRounds($barrier, $values, $id, $count);
};
$tm->run();
?>
--EXPECT--
DONE
