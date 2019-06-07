--TEST--
swoole_runtime/stream_select: Bug #53427 + emulate_read (stream_select does not preserve keys)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $read[1] = fopen(__FILE__, 'r');
    $read['myindex'] = reset($read);
    $write = null;
    $except = null;

    var_dump($read);
    stream_select($read, $write, $except, 0);
    var_dump($read);
    fread(reset($read), 1);
    stream_select($read, $write, $except, 0); // // emulate_read
    var_dump($read);
});
Swoole\Event::wait();
?>
--EXPECTF--
array(2) {
  [1]=>
  resource(%d) of type (stream)
  ["myindex"]=>
  resource(%d) of type (stream)
}
array(2) {
  [1]=>
  resource(%d) of type (stream)
  ["myindex"]=>
  resource(%d) of type (stream)
}
array(2) {
  [1]=>
  resource(%d) of type (stream)
  ["myindex"]=>
  resource(%d) of type (stream)
}
