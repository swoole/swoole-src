--TEST--
swoole_runtime: pdo full authentication over unix socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_database();
require_once __DIR__ . '/../include/config.php';
skip('no mysql unix socket', !file_exists(MYSQL_SERVER_PATH));
$pdo = new PDO('mysql:host=' . MYSQL_SERVER_HOST . ';port=' . MYSQL_SERVER_PORT, MYSQL_SERVER_USER, MYSQL_SERVER_PWD);
$status = $pdo->query("SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'caching_sha2_password'")->fetchColumn();
skip('require caching_sha2_password', $status !== 'ACTIVE');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
Co\run(function () {
    $root = new PDO(
        'mysql:host=' . MYSQL_SERVER_HOST . ';port=' . MYSQL_SERVER_PORT,
        MYSQL_SERVER_USER,
        MYSQL_SERVER_PWD
    );
    // A new account is not in the server's cache, so its first login needs full authentication
    $user = 'swoole_' . bin2hex(random_bytes(4));
    $root->exec("CREATE USER '{$user}'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'password'");
    try {
        $pdo = new PDO('mysql:unix_socket=' . MYSQL_SERVER_PATH, $user, 'password');
        var_dump($pdo->query('SELECT 1')->fetchColumn());
    } finally {
        $root->exec("DROP USER '{$user}'@'localhost'");
    }
});
?>
--EXPECT--
int(1)
