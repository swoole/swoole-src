--TEST--
swoole_mysql_coro: mysql fetchAll should return empty array (#2674)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $client = new Swoole\Coroutine\MySQL;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    ];

    if (Assert::true($client->connect($server))) {
        defer(function () use ($server, $client) {
            $client->connect($server);
            $client->query('DROP TABLE `empty`');
        });
        if (Assert::true($client->query("CREATE TABLE `empty` (`id` int(11))"))) {
            // query
            Assert::notEmpty($client->query('SELECT * FROM `ckl`'));
            Assert::eq($client->query('SELECT * FROM `empty`'), []);
            Assert::eq($client->query('SELECT * FROM `notexist`'), false);
            // execute
            Assert::notEmpty($client->prepare('SELECT * FROM `ckl`')->execute());
            Assert::eq(($statement = $client->prepare('SELECT * FROM `empty`'))->execute(), []);
            Assert::eq($client->prepare('SELECT * FROM `notexist`'), false);
            // closed
            Assert::true($client->close());
            Assert::eq($client->query('SELECT * FROM `empty`'), false);
            Assert::eq($client->prepare('SELECT * FROM `empty`'), false);
            Assert::eq($statement->execute(), false);

            if (Assert::true($client->connect($server + ['fetch_mode' => true]))) {
                // query
                Assert::true($client->query('SELECT * FROM `ckl` LIMIT 1'));
                Assert::notEmpty($client->fetch());
                Assert::null($client->fetch());
                Assert::null($client->fetch());
                Assert::eq($client->fetchAll(), []);
                Assert::true($client->query('SELECT * FROM `ckl` LIMIT 1'));
                Assert::count($client->fetchAll(), 1);
                Assert::eq($client->fetchAll(), []);
                // execute
                Assert::isInstanceOf(
                    $statement = $client->prepare('SELECT * FROM `ckl` LIMIT 1'),
                    Swoole\Coroutine\MySQL\Statement::class
                );
                Assert::eq($statement->fetchAll(), []);
                Assert::true($statement->execute());
                Assert::notEmpty($statement->fetch());
                Assert::null($statement->fetch());
                Assert::true($statement->execute());
                Assert::notEmpty($statement->fetchAll());
                Assert::eq($statement->fetchAll(), []);
                // closed
                Assert::true($client->close());
                Assert::false($client->query('SELECT * FROM `ckl` LIMIT 1'));
                Assert::false($client->fetch());
                Assert::false($client->fetchAll());
                Assert::false($statement->execute());
                Assert::false($statement->fetch());
                Assert::false($statement->fetchAll());
                echo "DONE\n";
            }
        }
    }
});
?>
--EXPECT--
DONE
