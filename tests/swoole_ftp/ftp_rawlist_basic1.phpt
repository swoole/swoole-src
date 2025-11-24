--TEST--
Testing ftp_rawlist basic functionality
--CREDITS--
Gabriel Caruso (carusogabriel34@gmail.com)
--FILE--
<?php
$fn = require 'server.inc';

Co\run(function () use ($fn) {
    $ftp = ftp_connect('127.0.0.1', $fn());
    ftp_login($ftp, 'user', 'pass');
    $ftp or die("Couldn't connect to the server");

    $result = ftp_rawlist($ftp, 'www/');
    var_dump(is_array($result));
    var_dump($result);
    ftp_close($ftp);
});
?>
--EXPECT--
bool(true)
array(3) {
  [0]=>
  string(5) "file1"
  [1]=>
  string(5) "file1"
  [2]=>
  string(9) "file
b0rk"
}