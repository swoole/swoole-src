--TEST--
swoole_coroutine: preserve configured and inherited error reporting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
error_reporting=0
--FILE--
<?php
$levels = [];
$record = function () use (&$levels) {
    $levels[] = error_reporting();
};

Swoole\Coroutine\run(function () use ($record) {
    Swoole\Coroutine::create($record);

    error_reporting(E_ERROR);
    Swoole\Coroutine::create($record);

    error_reporting(E_WARNING | E_NOTICE);
    @Swoole\Coroutine::create($record);

    ini_set('error_reporting', (string) E_WARNING);
    @Swoole\Coroutine::create($record);

    error_reporting(E_WARNING | E_NOTICE);
    $cid = Swoole\Coroutine::create(function () use ($record) {
        Swoole\Coroutine::yield();
        Swoole\Coroutine::create($record);
    });
    error_reporting(E_WARNING);
    Swoole\Coroutine::resume($cid);
});

var_dump($levels);
?>
--EXPECT--
array(5) {
  [0]=>
  int(0)
  [1]=>
  int(1)
  [2]=>
  int(10)
  [3]=>
  int(2)
  [4]=>
  int(10)
}
