--TEST--
Attempt to use a closed FTP\Connection
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");
    var_dump(ftp_login($ftp, 'user', 'pass'));
    var_dump(ftp_close($ftp));

    try {
        var_dump(ftp_login($ftp, 'user', 'pass'));
        echo "Login did not throw\n";
    } catch (ValueError $ex) {
        echo "Exception: ", $ex->getMessage(), "\n";
    }
});
?>
--EXPECT--
bool(true)
bool(true)
Exception: FTP\Connection is already closed