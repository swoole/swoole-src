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
                Co::yield();
                // ......
                $list = Co::list();
                $list->asort();
                foreach ($list as $cid) {
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
swoole_event_wait();
?>
--EXPECTF--
int(1)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(31)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#%d (0) {
      }
    }
  }
}
int(2)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(30)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#%d (0) {
      }
    }
  }
}
int(3)
array(1) {
  [0]=>
  array(4) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(29)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#%d (1) {
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
    string(%d) "%s"
    ["line"]=>
    int(13)
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
    string(%d) "%s"
    ["line"]=>
    int(28)
    ["function"]=>
    string(2) "go"
    ["args"]=>
    array(1) {
      [0]=>
      object(Closure)#%d (1) {
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
    string(%d) "%s"
    ["line"]=>
    int(18)
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
    string(%d) "%s"
    ["line"]=>
    int(21)
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
int(8)
array(1) {
  [0]=>
  array(6) {
    ["file"]=>
    string(%d) "%s"
    ["line"]=>
    int(24)
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
    string(%d) "%s"
    ["line"]=>
    int(27)
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
