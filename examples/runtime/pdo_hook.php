<?php
// With PDO hooks enabled, database calls yield instead of blocking the loop.
// Run: php examples/runtime/pdo_hook.php
use function Swoole\Coroutine\run;

if (!extension_loaded('pdo_sqlite')) {
    echo 'pdo_sqlite is required' . PHP_EOL;
    return;
}

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_SQLITE);

run(function () {
    $pdo = new PDO('sqlite::memory:');
    $pdo->exec('CREATE TABLE t (id INTEGER)');
    $pdo->exec('INSERT INTO t VALUES (1)');
    echo 'rows: ', $pdo->query('SELECT COUNT(*) FROM t')->fetchColumn(), PHP_EOL;
});
