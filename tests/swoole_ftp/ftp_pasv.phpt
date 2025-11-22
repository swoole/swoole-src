--TEST--
Testing ftp_pasv basic funcionality
--CREDITS--
Gabriel Caruso (carusogabriel34@gmail.com)
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    ftp_login($ftp, 'user', 'pass');
    $ftp or die("Couldn't connect to the server");

    var_dump(ftp_pasv($ftp, false));
});
?>
--EXPECT--
bool(true)