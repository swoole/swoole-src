--TEST--
swoole_coroutine/join: 8
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

ini_set('swoole.display_errors', 'off');

run(function () {
    $cid_list[] = 88888;
    $cid_list[] = 99999;
    Assert::false(Coroutine::join($cid_list));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
