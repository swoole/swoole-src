--TEST--
ftp_mlsd() must not return false on empty directories
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'user', 'pass'));

    var_dump(ftp_mlsd($ftp, 'emptydir'));
    var_dump(ftp_mlsd($ftp, 'bogusdir'));

    ftp_close($ftp);
});
?>
--EXPECT--
bool(true)
array(0) {
}
bool(false)