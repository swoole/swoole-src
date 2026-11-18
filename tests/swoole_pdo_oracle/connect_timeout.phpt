--TEST--
swoole_pdo_oracle: connection handshake timeout does not block other coroutines
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HOOK_PDO_ORACLE');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// The TCP handshake completes, but this listener never answers the Oracle handshake.
// No Oracle database is needed for this test.
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];
$dsn = sprintf(
    'oci:dbname=(DESCRIPTION=(CONNECT_TIMEOUT=1)(TRANSPORT_CONNECT_TIMEOUT=1)(RETRY_COUNT=0)'
    . '(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=%d))'
    . '(CONNECT_DATA=(SERVICE_NAME=swoole_test)))',
    $port
);

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_ORACLE);
Co\run(function () use ($dsn): void {
    $otherCoroutineRan = false;
    go(function () use (&$otherCoroutineRan): void {
        Co::sleep(0.01);
        $otherCoroutineRan = true;
    });

    $timedOut = false;
    try {
        new PDO($dsn, 'user', 'password');
    } catch (PDOException $exception) {
        Assert::contains($exception->getMessage(), 'ORA-12170');
        $timedOut = true;
    }
    Assert::true($timedOut);
    // Check before yielding again: running the other coroutine after the timeout is too late.
    Assert::true($otherCoroutineRan);
});

fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
