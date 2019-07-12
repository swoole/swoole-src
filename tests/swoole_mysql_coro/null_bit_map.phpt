--TEST--
swoole_mysql_coro: mysql null bit map rand test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function gen_type(): string
{
    static $types = ['bigint', 'varchar(255)'];
    return $types[array_rand($types)];
}

function gen_data_from_type(string $type)
{
    switch ($type) {
        case 'bigint':
            return mt_rand(1, PHP_INT_MAX);
        case 'varchar(255)':
            return sha1(mt_rand());
        default:
            return null;
    }
}

function mysql(): Co\MySQL
{
    $mysql = new Co\MySQL;
    $connected = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    Assert::assert($connected);
    return $mysql;
}

for ($c = MAX_CONCURRENCY_LOW; $c--;) {
    go(function () use ($c) {
        // gen table structure
        $table_name = 't' . substr(md5(mt_rand()), 0, 15);
        $field_size = mt_rand(1, 100);
        list($fields, $fields_info) = (function () use ($field_size) {
            $fields_info = [];
            $fields = '';
            for ($i = $field_size; $i--;) {
                $info = $fields_info[] = [
                    'name' => 'f' . substr(md5(mt_rand()), 0, 7),
                    'type' => gen_type()
                ];
                $fields .= "{$info['name']} {$info['type']} NULL,\n";
            }
            return [rtrim($fields, " \n,"), $fields_info];
        })();
        $mysql = mysql();
        // create table
        $createTable = <<<SQL
CREATE TABLE {$table_name} (
id bigint PRIMARY KEY AUTO_INCREMENT,
{$fields}
);
SQL;
        // gen data and insert
        if (!$mysql->query($createTable)) {
            trigger_error("create table error by query statement [{$createTable}]", E_USER_WARNING);
            return;
        }
        $_insert = "INSERT INTO {$table_name} VALUES (" . rtrim(str_repeat('?, ', $field_size + 1), ', ') . ")";
        $data_list = [];
        try {
            for ($n = MAX_REQUESTS; $n--;) {
                $insert = $mysql->prepare($_insert);
                Assert::assert($insert instanceof Co\Mysql\Statement);
                $data_list[] = $gen = (function ($id, $fields_info) {
                    $r = ['id' => $id];
                    foreach ($fields_info as $info) {
                        if (mt_rand(0, 1)) {
                            $r[$info['name']] = null;
                        } else {
                            $r[$info['name']] = gen_data_from_type($info['type']);
                        }
                    }
                    return $r;
                })($n + 1, $fields_info);
                Assert::assert($insert->execute(array_values($gen)));
            }
            $result = $mysql->prepare("SELECT * FROM {$table_name}")->execute();
            Assert::same(array_reverse($data_list), $result);
        } catch (Throwable $e) {
            Assert::assert(0);
        } finally {
            Assert::assert($mysql->query("DROP TABLE {$table_name}"));
        }
    });
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
