--TEST--
swoole_mysql: simple insert
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('onClose event lost');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_init.php';

fork_exec(function () {
    $sql = <<<SQL
INSERT INTO `test`.`userinfo`
(`name`, `level`, `passwd`, `regtime`, `big_n`, `data`, `lastlogin_ip`, `price`, `mdate`, `mtime`, `mdatetime`, `year`, `int8_t`, `mshort`, `mtext`)
VALUES
('jack', 199, 'xuyou', '2015-01-01 18:00:00', 999000, 'null', 1270, 0.22, '1997-06-04', '21:52:33', '2018-04-17 04:16:20', 1989, 127, 32767, '');
SQL;
    swoole_mysql_query($sql, function (swoole_mysql $swoole_mysql, $result) {
        ob_start();
        assert($result === true);
        assert($swoole_mysql->errno === 0);
        if ($buf = ob_get_clean())
        {
            echo $buf;
        }
        assert($swoole_mysql->insert_id > 0);
        echo "SUCCESS\n";
        $swoole_mysql->close();
        swoole_event_exit();
    });
});
?>
--EXPECT--
SUCCESS
closed
