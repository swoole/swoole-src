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
Swoole\Event::wait();
?>
--EXPECTF--
int(1)
array(%d) {
  %A
}
int(2)
array(%d) {
  %A
}
int(3)
array(%d) {
  %A
}
int(4)
array(%d) {
  %A
}
int(5)
array(%d) {
  %A
}
int(6)
array(%d) {
  %A
}
int(7)
array(%d) {
  %A
}
int(8)
array(%d) {
  %A
}
int(9)
array(%d) {
  %A
}
