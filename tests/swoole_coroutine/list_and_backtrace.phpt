--TEST--
swoole_coroutine: getBackTrace form listCoroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    go(function () {
        go(function () {
            $main = go(function () {
                $coros = Co::listCoroutines();
                Co::yield();
                foreach ($coros as $cid) {
                    var_dump($cid);
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
                go(function () use ($main) {
                    Co::resume($main);
                });
            });
        });
    });
});
?>
--EXPECTF--
int(1)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(29)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#2 (0) {
      }
    }
  }
}
int(2)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(28)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#3 (0) {
      }
    }
  }
}
int(3)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(27)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#6 (1) {
        ["static"]=>
        array(1) {
          ["main"]=>
          int(4)
        }
      }
    }
  }
}
int(4)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(11)
    ["function"]=>
    string(12) "getBackTrace"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      int(4)
    }
  }
}
int(5)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(26)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#10 (1) {
        ["static"]=>
        array(1) {
          ["main"]=>
          int(4)
        }
      }
    }
  }
}
int(6)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(16)
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
int(7)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(19)
    ["function"]=>
    string(8) "readFile"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    }
  }
}
int(8)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(22)
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
int(9)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s/tests/swoole_coroutine/list_and_backtrace.php"
    ["line"]=>
    int(25)
    ["function"]=>
    string(6) "resume"
    ["class"]=>
    string(16) "Swoole\Coroutine"
    ["type"]=>
    string(2) "::"
    ["args"]=>
    array(1) {
      [0]=>
      int(4)
    }
  }
}
