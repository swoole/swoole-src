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

$count = 0;
$running = true;

Co\run(function () {
    $fp = fopen("async.file://" . TEST_IMAGE, "r");
    $content = '';

    Co\go(function () {
        global $count, $running;
        while($running) {
            usleep(1000);
            $count++;
        }   
    });

    while(!feof($fp)) {
        $content .= fread($fp, 512);
    }
    fclose($fp);

    global $count, $running;
    $running = false;
    // Iouring is too fast, no coroutine switching will occur, and the file has already been completed
    if (!defined('SWOOLE_IOURING_DEFAULT')) {
        Assert::true($count >= 1);
    }
    Swoole\Runtime::enableCoroutine(false);
    Assert::same(md5($content), md5_file(TEST_IMAGE));
});
?>
--EXPECT--
