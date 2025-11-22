--TEST--
Testing ftp_chmod returns file mode
--CREDITS--
Rodrigo Moyle <eu [at] rodrigorm [dot] com [dot] br>
#testfest PHPSP on 2009-06-20
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");
    ftp_login($ftp, 'user', 'pass');

    var_dump(ftp_chmod($ftp, 0644, 'test.txt'));
});
?>
--EXPECT--
int(420)