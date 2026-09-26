--TEST--
swoole_windows: IOCP skips readiness for replaced file descriptors
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Timer;

$files = [tmpfile(), tmpfile()];
$fds = [];
$replacement = null;
$handled = false;

$callback = function ($stream) use (&$files, &$fds, &$replacement, &$handled) {
    Assert::false($handled);
    $handled = true;
    $current = $stream === $files[0] ? 0 : 1;
    $other = 1 - $current;

    Assert::true(Event::del($files[$other]));
    fclose($files[$other]);
    $files[$other] = null;

    $replacement = tmpfile();
    $replacementFd = Event::add($replacement, static function ($stream) {
        Event::del($stream);
        Event::exit();
        echo "UNEXPECTED\n";
    });
    Assert::same($replacementFd, $fds[$other]);

    Assert::true(Event::del($stream));
    Event::defer(static function () {
        Event::exit();
    });
};

$fds[] = Event::add($files[0], $callback);
$fds[] = Event::add($files[1], $callback);
Timer::after(1000, static function () {
    Event::exit();
});
Event::wait();

Assert::true($handled);
if ($replacement) {
    if (Event::isset($replacement)) {
        Event::del($replacement);
    }
    fclose($replacement);
}
foreach ($files as $file) {
    if ($file) {
        fclose($file);
    }
}

echo "DONE\n";
?>
--EXPECT--
DONE
