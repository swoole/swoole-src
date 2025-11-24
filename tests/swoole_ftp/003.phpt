--TEST--
FTP cwd
--FILE--
<?php
$fn = require 'server.inc';
Co\run(function () use ($fn){
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'user', 'pass'));

    var_dump(ftp_pwd($ftp));

    var_dump(ftp_chdir($ftp, 'mydir'));
    var_dump(ftp_pwd($ftp));

    var_dump(ftp_chdir($ftp, '/xpto/mydir'));
    var_dump(ftp_pwd($ftp));

    var_dump(ftp_cdup($ftp));
    var_dump(ftp_pwd($ftp));

    var_dump(ftp_chdir($ftp, '..'));
    var_dump(ftp_pwd($ftp));

    var_dump(ftp_close($ftp));
});
?>
--EXPECT--
bool(true)
string(1) "/"
bool(true)
string(6) "/mydir"
bool(true)
string(11) "/xpto/mydir"
bool(true)
string(5) "/xpto"
bool(true)
string(1) "/"
bool(true)
