<?php

go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => 'root',
        'database' => 'test'
    ];

    $clear = <<<SQL
    DROP PROCEDURE IF EXISTS `say`
SQL;
    $procedure = <<<SQL
  CREATE DEFINER=`root`@`localhost` PROCEDURE `say`(content varchar(255))
  BEGIN
    SELECT concat('you said: \"', content, '\"');
  END
SQL;

    $db->connect($server);
    if ($db->query($clear) && $db->query($procedure)) {
        $stmt = $db->prepare('CALL say(?)');
        $ret = $stmt->execute(['hello mysql!']);
        var_dump(current($ret[0])); // you said: "hello mysql!"
    }
});
