+--TEST--
+swoole_coroutine: redis zcount
+--SKIPIF--
+<?php require  __DIR__ . "/../../include/skipif.inc"; ?>
+--FILE--
+<?php
+require_once __DIR__ . "/../../include/swoole.inc";
+require_once __DIR__ . "/../../include/lib/curl.php";
+
+go(function () {
+    $redis = new \Swoole\Coroutine\Redis();
+    $result = $redis->connect('127.0.0.1', 6379, false);
+    assert($result);
+
+    assert($redis->zadd('u:i', 1, 1));
+    assert($redis->zadd('u:i', 2, 2));
+    assert($redis->zcount('u:i', 0, 1) == 1);
+    assert($redis->zcount('u:i', 0, '+inf') == 2);
+});
+?>
+--EXPECT--
+
