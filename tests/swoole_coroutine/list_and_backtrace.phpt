--TEST--
swoole_coroutine: getBackTrace form listCoroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$main = go(function () {
    Co::yield();
    $coros = Co::listCoroutines();
    foreach ($coros as $cid) {
        var_dump(Co::getBackTrace($cid));
    }
});
go(function () use ($main) {
    go(function () {
        Co::sleep(0.001);
    });
    go(function () {
        Co::readFile(__FILE__);
    });
    go(function () {
        Co::getaddrinfo('localhost');
    });
    Co::resume($main);
});
?>
--EXPECTF--
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(%d)
    ["function"]=>
    string(12) "getBackTrace"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      int(1)
    }
  }
}
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(%d)
    ["function"]=>
    string(6) "resume"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      int(1)
    }
  }
}
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(%d)
    ["function"]=>
    string(5) "sleep"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      float(0.001)
    }
  }
}
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(%d)
    ["function"]=>
    string(8) "readFile"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      string(%d) "%s"
    }
  }
}
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(%d)
    ["function"]=>
    string(11) "getaddrinfo"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      string(9) "localhost"
    }
  }
}