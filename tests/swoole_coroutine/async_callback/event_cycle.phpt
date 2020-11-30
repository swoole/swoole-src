--TEST--
swoole_coroutine/async_callback: event cycle
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;

const N = 4;

$GLOBALS['count'] = 0;
$GLOBALS['logs'] = [];

Co\run(function () {
    Event::cycle(function () {
        $GLOBALS['count']++;
        if ($GLOBALS['count'] == N) {
            Event::cycle(null);
        }
        Co::sleep(0.02);
        $GLOBALS['logs'] [] = "cycle\n";
    });

    $n = N;
    while ($n--) {
        Co::sleep(0.01);
        $GLOBALS['logs'] [] = "sleep\n";
    }
});

$str = implode('', $GLOBALS['logs']);
Assert::eq(substr_count($str, 'cycle'), N);
Assert::eq(substr_count($str, 'sleep'), N);
?>
--EXPECT--
