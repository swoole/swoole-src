--TEST--
swoole_mysql_coro: illegal child class
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

class swoole_invalid_mysql_coro extends \Swoole\Coroutine\MySQL
{

    public function __construct()
    {
        // miss parent::__construct
    }

    public function connect(array $server_config)
    {
        // miss parent::connect
        return true;
    }

    public function connectRaw(array $server_config)
    {
        return parent::connect($server_config);
    }

    public function __destruct()
    {
        // miss parent::__destruct
    }

}

go(function () {
    $db = new swoole_invalid_mysql_coro;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => true
    ];

    // invalid connect
    Assert::assert($db->connect($server));
    Assert::assert(!$db->connected);
    Assert::assert(!$db->query('select 1'));

    // right implementation
    Assert::assert($db->connectRaw($server));
    Assert::eq($db->query('select 1')[0][1], 1);
});

?>
--EXPECTF--
Warning: Swoole\Coroutine\MySQL::query(): mysql connection#%d is closed in %s on line %d