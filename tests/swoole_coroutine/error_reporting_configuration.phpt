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

    ini_set('error_reporting', (string) E_WARNING);
    @Swoole\Coroutine::create($record);

    foreach ([0, E_ERROR, E_WARNING | E_NOTICE] as $level) {
        error_reporting(E_ALL);
        $cid = Swoole\Coroutine::create(function () use ($level, $record) {
            error_reporting($level);
            Swoole\Coroutine::yield();
            Swoole\Coroutine::create($record);
            @Swoole\Coroutine::create($record);
        });
        error_reporting(E_WARNING);
        Swoole\Coroutine::resume($cid);
    }

    error_reporting(E_WARNING | E_NOTICE);
    $nested = function () use ($record) {
        @Swoole\Coroutine::create($record);
    };
    @$nested();
});

var_dump($levels);
?>
--EXPECT--
array(9) {
  [0]=>
  int(0)
  [1]=>
  int(2)
  [2]=>
  int(0)
  [3]=>
  int(0)
  [4]=>
  int(1)
  [5]=>
  int(1)
  [6]=>
  int(10)
  [7]=>
  int(10)
  [8]=>
  int(10)
}
