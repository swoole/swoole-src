--TEST--
Bug #27809 (ftp_systype returns null)
--FILE--
<?php
$bug27809=true;
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'anonymous', 'IEUser@'));
    var_dump(ftp_systype($ftp));
});
?>
--EXPECT--
bool(true)
string(6) "OS/400"
