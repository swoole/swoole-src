--TEST--
swoole_coroutine: interrupt: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Co::cancel(go(function () {
    $ret = Co::sleep(1);
    assert(is_double($ret));
    assert(time_approximate(1, $ret));
    var_dump(Co::wasCancelled());
}));

Co::shutdown(go(function () {
    Co::yield();
    echo "never here\n";
}));

Co::throw(go(function () {
    try {
        Co::yield();
    } catch (Co\Exception $e) {
        var_dump($e);
    }
}));

?>
--EXPECTF--
bool(true)
object(Swoole\Coroutine\Exception)#1 (12) {
  ["message":protected]=>
  string(%d) "the coroutine was interrupted by an exception from cid#-1."
  ["string":"Exception":private]=>
  string(%d) ""
  ["code":protected]=>
  int(%d)
  ["file":protected]=>
  string(%d) "%s/tests/swoole_coroutine/interrupt/base.php"
  ["line":protected]=>
  int(%d)
  ["trace":"Exception":private]=>
  array(1) {
    [0]=>
    array(6) {
      ["file"]=>
      string(%d) "%s/tests/swoole_coroutine/interrupt/base.php"
      ["line"]=>
      int(%d)
      ["function"]=>
      string(%d) "yield"
      ["class"]=>
      string(%d) "Swoole\Coroutine"
      ["type"]=>
      string(%d) "::"
      ["args"]=>
      array(0) {
      }
    }
  }
  ["previous":"Exception":private]=>
  NULL
  ["cid":protected]=>
  int(%d)
  ["originCid":protected]=>
  int(-1)
  ["originFile":protected]=>
  string(%d) "%s/tests/swoole_coroutine/interrupt/base.php"
  ["originLine":protected]=>
  int(%d)
  ["originTrace":protected]=>
  array(1) {
    [0]=>
    array(6) {
      ["file"]=>
      string(%d) "%s/tests/swoole_coroutine/interrupt/base.php"
      ["line"]=>
      int(%d)
      ["function"]=>
      string(%d) "throw"
      ["class"]=>
      string(%d) "Swoole\Coroutine"
      ["type"]=>
      string(%d) "::"
      ["args"]=>
      array(1) {
        [0]=>
        int(%d)
      }
    }
  }
}
