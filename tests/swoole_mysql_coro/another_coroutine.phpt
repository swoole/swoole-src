--TEST--
swoole_mysql_coro: illegal another coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_unsupported();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$process = new Swoole\Process(function () {
    function get(Co\Mysql $cli)
    {
        $cli->query('SELECT SLEEP(1)');
        Assert::assert(false, 'never here');
    }

    $cli = new Co\MySQL;
    $connected = $cli->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    Assert::true($cli->setDefer());
    Assert::true($connected);
    if ($connected) {
        go(function () use ($cli) {
            $cli->query('SELECT SLEEP(1)');
            Assert::assert(false, 'never here');
        });
        go(function () use ($cli) {
            (function () use ($cli) {
                (function () use ($cli) {
                    get($cli);
                })();
            })();
        });
    }
    Swoole\Event::wait();
}, false, null, true);
$process->start();
Swoole\Process::wait();
?>
--EXPECTF--
mysql client is busy now, %s
[%s]    ERROR    (PHP Fatal Error: %d):
Swoole\Coroutine\MySQL::recv: Socket#%d has already been bound to another coroutine#%d, reading of the same socket in multiple coroutines at the same time is not allowed
Stack trace:
#0  Swoole\Coroutine\MySQL->recv() called at [%s/tests/swoole_mysql_coro/another_coroutine.php:%d]
#1  get() called at [%s/tests/swoole_mysql_coro/another_coroutine.php:%d]
#2  {closure}() called at [%s/tests/swoole_mysql_coro/another_coroutine.php:%d]
#3  {closure}() called at [%s/tests/swoole_mysql_coro/another_coroutine.php:%d]
