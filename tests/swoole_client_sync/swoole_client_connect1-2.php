<?php
/**

 * Time: 上午10:06
 */
require_once __DIR__ . "/../include/swoole.inc";

killself_in_syncmode(1000, SIGTERM);


$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = $cli->connect(IP_BAIDU, 80);
assert($r);
$cli->close();
echo "SUCCESS";
?>

