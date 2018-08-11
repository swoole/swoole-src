--TEST--
swoole_coroutine_channel: the bug about timeout timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; 
exit("skip for select");
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
// this sript will hanging up and remove out of tests
// $chan = new chan(1);

// go(function () use ($chan) {
//     co::sleep(0.1);
//     $chan->push('foo');
// });

// go(function () use ($chan) {
//     $read = [
//         $chan
//     ];
//     $write = [];
//     $ret = chan::select($read, $write, 0.1);
//     assert($ret === true);
//     assert(count($read) === 1);
// });
?>
--EXPECT--