--TEST--
swoole_runtime/file_hook: async file
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

// disable file hook
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL & ~SWOOLE_HOOK_FILE);

Co\run(function () {
    $finished = false;
    $content = '';
    $cid = Co\go(function () use (&$finished, &$content) {
        $fp = fopen("async.file://" . TEST_IMAGE, "r");
        while (!feof($fp)) {
            $content .= fread($fp, 512);
        }
        fclose($fp);
        $finished = true;
    });

    // Thread-pool I/O must yield before the reader finishes; no timer needs to fire.
    // io_uring may complete a cached read without yielding.
    if (!defined('SWOOLE_IOURING_DEFAULT')) {
        Assert::false($finished);
    }
    Co::join([$cid]);
    Assert::true($finished);
    Swoole\Runtime::enableCoroutine(false);
    Assert::same(md5($content), md5_file(TEST_IMAGE));
});
?>
--EXPECT--
