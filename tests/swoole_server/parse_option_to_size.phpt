--TEST--
swoole_server: parse option value to size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.2.0');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0);
$server->set([
    'buffer_output_size' => '2M',
]);
$server->set([
    'buffer_output_size' => 2 * 1024 * 1024,
]);
$server->set([
    'buffer_output_size' => 'xxx--2M',
]);
?>
--EXPECTF--
Fatal error: Swoole\Server::set(): failed to parse 'xxx--2M' to size, Error: Invalid quantity "xxx--2M": no valid leading digits, interpreting as "0" for backwards compatibility in %s on line %d

