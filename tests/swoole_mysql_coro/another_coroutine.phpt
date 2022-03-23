--TEST--
swoole_mysql_coro: illegal another coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$process = new Swoole\Process(function () {
    go(function () {
        register_shutdown_function(function () {
            $msg = (error_get_last() ?? [])['message'] ?? '';
            $num = preg_match_all('/coroutine#(\d+)/', $msg, $matches);
            if (Assert::same($num, 2)) {
                $matches = $matches[1];
                $bound_co = (int)$matches[0];
                $error_co = (int)$matches[1];
                $bound_co_trace = Co::getBackTrace($bound_co);
                $error_co_trace = Co::getBackTrace($error_co);
                Assert::same($bound_co_trace[0]['object'], $error_co_trace[0]['object']);
                echo "DONE\n";
            }
        });

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
        if (Assert::true($connected)) {
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
    });
}, false, null, false);
$process->start();
Swoole\Process::wait();
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: Socket#%d has already been bound to another coroutine#%d, reading of the same socket in coroutine#%d at the same time is not allowed in %s:%d
Stack trace:
#0 %s(%d): Swoole\Coroutine\MySQL->query('SELECT SLEEP(%d)')
#1 %s(%d): get(Object(Swoole\Coroutine\MySQL))
#2 %s(%d): {closure}()
#3 %s(%d): {closure}()
#4 {main}
  thrown in %s on line %d
DONE
