--TEST--
swoole_mysql: query multifield
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_mysql/swoole_mysql_init.php";

define('FIELD_NUM', 8192);

$n = range(0, FIELD_NUM - 1);
$fields = implode(", ", $n);

swoole_mysql_query("select $fields", function ($swoole_mysql, $result)
{
    global $fields;
    assert(count($result[0]) == FIELD_NUM);
    assert($swoole_mysql->errno === 0);
    $swoole_mysql->query("select $fields", function ($swoole_mysql, $result)
    {
        assert(count($result[0]) == FIELD_NUM);
        $swoole_mysql->close();
    });
});
Swoole\Event::wait();
?>
--EXPECT--
closed
