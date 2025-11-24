--TEST--
GH-10521 (ftp_get/ftp_nb_get resumepos offset is maximum 10GB)
--SKIPIF--
<?php
if (PHP_INT_SIZE != 8) die("skip: 64-bit only");
?>
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    if (!$ftp) die("Couldn't connect to the server");

    var_dump(ftp_login($ftp, 'anonymous', 'IEUser@'));

    $local_file = __DIR__ . DIRECTORY_SEPARATOR . "gh10521.txt";

    foreach ([12345678910, 9223372036854775807] as $size) {
        $handle = fopen($local_file, 'w');
        // Doesn't actually succeed in transferring a file. The file transfer gets aborted by our fake server.
        // We just want to see if the offset was correctly received.
        ftp_fget($ftp, $handle, 'gh10521', FTP_ASCII, $size);
        fclose($handle);
    }
});
?>
--CLEAN--
<?php
@unlink(__DIR__ . DIRECTORY_SEPARATOR . "gh10521.txt");
?>
--EXPECTF--
bool(true)

%s: ftp_fget(): Can't open data connection (12345678910). in %s on line %d

%s: ftp_fget(): Can't open data connection (9223372036854775807). in %s on line %d