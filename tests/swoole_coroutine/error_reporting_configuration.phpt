--TEST--
swoole_coroutine: snapshot the configured default once per coroutine environment
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
            if (error_reporting() !== $level) {
                throw new RuntimeException('The creator must retain its local level across suspension');
            }
            Swoole\Coroutine::create($record);
            @Swoole\Coroutine::create($record);
            if (error_reporting() !== $level) {
                throw new RuntimeException('Child creation must preserve the creator level');
            }
        });
        error_reporting(E_WARNING);
        Swoole\Coroutine::resume($cid);
    }

    error_reporting(E_WARNING | E_NOTICE);
    $nested = function () use ($record) {
        @Swoole\Coroutine::create($record);
    };
    @$nested();

    error_reporting(E_ALL);
    @(error_reporting(E_WARNING) && @Swoole\Coroutine::create($record));
});

if (error_reporting() !== 0) {
    throw new RuntimeException('The main context must retain its original level');
}

// A new coroutine environment takes a fresh snapshot, including when initialized under @.
ini_set('error_reporting', (string) E_WARNING);
@Swoole\Coroutine\run(function () use ($record) {
    Swoole\Coroutine::create($record);
    @Swoole\Coroutine::create($record);
});

var_dump($levels);
?>
--EXPECT--
array(12) {
  [0]=>
  int(0)
  [1]=>
  int(0)
  [2]=>
  int(0)
  [3]=>
  int(0)
  [4]=>
  int(0)
  [5]=>
  int(0)
  [6]=>
  int(0)
  [7]=>
  int(0)
  [8]=>
  int(0)
  [9]=>
  int(0)
  [10]=>
  int(2)
  [11]=>
  int(2)
}
