--TEST--
Testing ftp_fput basic functionality
--CREDITS--
Gabriel Caruso (carusogabriel34@gmail.com)
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    ftp_login($ftp, 'user', 'pass');
    $ftp or die("Couldn't connect to the server");

    $destination_file = basename(__FILE__);
    $source_file = fopen(__FILE__, 'r');

    var_dump(ftp_fput($ftp, $destination_file, $source_file, FTP_ASCII));
});
?>
--EXPECT--
bool(true)