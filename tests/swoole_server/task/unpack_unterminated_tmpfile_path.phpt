--TEST--
swoole_server/task: reject an unterminated tmpfile path before opening it
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server\Task;

swoole_ignore_error(SWOOLE_ERROR_PACKAGE_MALFORMED_DATA);
$data = str_repeat('payload', 4096);
$packed = Task::pack($data);
$headerLength = strlen(Task::pack(''));
$invalid = substr($packed, 0, $headerLength) . str_repeat('a', strlen($packed) - $headerLength);

try {
    Assert::false(@Task::unpack($invalid));
    Assert::same(swoole_last_error(), SWOOLE_ERROR_PACKAGE_MALFORMED_DATA);
} finally {
    Assert::same(Task::unpack($packed), $data);
}
?>
--EXPECT--
