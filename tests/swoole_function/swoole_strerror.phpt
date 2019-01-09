--TEST--
swoole_function: swoole_strerror
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
echo swoole_strerror(IS_MAC_OS ? 4 : -4 /*EAI_FAIL*/, SWOOLE_STRERROR_GAI) . "\n";
echo swoole_strerror(2 /*NO_ADDRESS*/, SWOOLE_STRERROR_DNS) . "\n";
echo swoole_strerror(SOCKET_ECONNRESET) . "\n";
echo swoole_strerror(SWOOLE_ERROR_FILE_NOT_EXIST) . "\n";
assert(
    swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL - 1)
    ===
    swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL - 1, SWOOLE_STRERROR_SWOOLE)
);
?>
--EXPECT--
Non-recoverable failure in name resolution
Host name lookup failure
Connection reset by peer
File not exist
