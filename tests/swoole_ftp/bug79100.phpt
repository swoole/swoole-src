--TEST--
Bug #79100 (Wrong FTP error messages)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
$GLOBALS['bug79100'] = true;
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $port = $fn();
    $ftp = ftp_connect("127.0.0.1", $port);
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'user', 'pass'));
    var_dump(ftp_set_option($ftp, FTP_TIMEOUT_SEC, 1));
    ftp_systype($ftp);

    ftp_close($ftp);
});
?>
--EXPECTF--
bool(true)
bool(true)

Warning: ftp_systype(): %rConnection|Operation%r timed out in %s on line %d
