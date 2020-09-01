--TEST--
swoole_mysql_coro: mysql prepare multi (insert and delete)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($c = MAX_CONCURRENCY_LOW; $c--;) {
    go(function () {
        $db = new Co\MySQL();
        $server = [
            'host' => MYSQL_SERVER_HOST,
            'port' => MYSQL_SERVER_PORT,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB,
        ];
        $connected = $db->connect($server);
        if (!$connected) {
            echo "CONNECT ERROR\n";
            return;
        }
        for ($n = MAX_REQUESTS_MID; $n--;) {
            $statement = $db->prepare('INSERT INTO ckl (`domain`,`path`,`name`) VALUES (?, ?, ?)');
            if (!$statement) {
                echo "PREPARE ERROR\n";
                return;
            }
            $executed = $statement->execute(['www.baidu.com', '/search', 'baidu']);
            if (!$executed) {
                echo "EXECUTE ERROR\n";
                return;
            }
            if ($statement->insert_id > 0) {
                $deleted = $db->query("DELETE FROM ckl WHERE id={$statement->insert_id}");
                if (!$deleted) {
                    echo "DELETE ERROR\n";
                }
            } else {
                echo "INSERT ERROR\n";
            }
        }
    });
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
