--TEST--
ssh2_sftp - SFTP tests
--SKIPIF--
<?php
  require('ssh2_skip.inc');
  ssh2t_needs_auth();
  ssh2t_writes_remote();
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
ssh2t_auth($ssh);
$sftp = ssh2_sftp($ssh);

$filename = ssh2t_tempnam();

$fp = fopen("ssh2.sftp://$sftp/$filename", 'w');
fwrite($fp, "Hello World\n");
fwrite($fp, "Goodbye Planet\n");
fclose($fp);

readfile("ssh2.sftp://$sftp/$filename");

var_dump(ssh2_sftp_unlink($sftp, $filename));
--EXPECT--
Hello World
Goodbye Planet
bool(true)
