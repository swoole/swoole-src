--TEST--
Verify php can handle filesizes >32bit
--SKIPIF--
<?php
if (2147483647 == PHP_INT_MAX) {
    die('skip 64-bit only');
}
?>
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    ftp_login($ftp, 'user', 'pass');
    var_dump(ftp_size($ftp, 'largefile'));

    ftp_close($ftp);
});
?>
--EXPECT--
int(5368709120)