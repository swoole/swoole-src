--TEST--
FTP with bogus parameters
--FILE--
<?php
$fn = require 'server.inc';
Co\run(function () use ($fn){
    // Negative timeout
    try {
        ftp_connect('127.0.0.1', 0, -3);
    } catch (ValueError $exception) {
        echo $exception->getMessage() . "\n";
    }

    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'user', 'pass'));
    var_dump(ftp_login($ftp, 'user', 'bogus'));

    var_dump(ftp_quit($ftp));
});
?>
--EXPECTF--
ftp_connect(): Argument #3 ($timeout) must be greater than 0
bool(true)

Warning: ftp_login(): Not logged in. in %s on line %d
bool(false)
bool(false)
