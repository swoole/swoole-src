--TEST--
swoole_mysql_coro: kill process and check liveness
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $config = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => true
    ];
    $mysql = new Swoole\Coroutine\MySQL;
    Assert::true($mysql->connect($config));
    Assert::same($mysql->query('SELECT 1')[0][1], 1);

    $killer = new Swoole\Coroutine\MySQL;
    Assert::true($killer->connect($config));

    foreach (
        [
            function () use ($mysql) {
                return $mysql->query('SELECT 1');
            },
            function () use ($mysql) {
                return $mysql->begin();
            },
            function () use ($mysql) {
                return $mysql->prepare('SELECT 1');
            },
        ] as $command
    ) {
        $processList = $killer->query('show processlist');
        $processList = array_filter($processList, function (array $value) {
            return $value['db'] == MYSQL_SERVER_DB && $value['Info'] != 'show processlist';
        });
        foreach ($processList as $process) {
            $killer->query("KILL {$process['Id']}");
        }
        switch_process();
        Assert::false($command());
        Assert::same($mysql->errno, SWOOLE_MYSQLND_CR_SERVER_GONE_ERROR);
        Assert::true($mysql->connect($config));
    }

    echo $mysql->error . PHP_EOL;
});
echo "DONE\n";
?>
--EXPECT--
SQLSTATE[HY000] [2006] MySQL server has gone away
DONE
