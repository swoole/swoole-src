--TEST--
FTP basic ftp_rename calls
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    ftp_login($ftp, 'user', 'pass');

    var_dump(ftp_rename($ftp, 'existing_file', 'nonexisting_file'));
    var_dump(ftp_rename($ftp, 'nonexisting_file', 'nonexisting_file'));
});
?>
--EXPECTF--
bool(true)

Warning: ftp_rename(): No such file or directory in %sftp_rename_basic1.php on line %d
bool(false)
