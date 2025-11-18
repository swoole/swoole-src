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
$linkname = ssh2t_tempnam();

var_dump(ssh2_sftp_mkdir($sftp, $filename, 0644, true));
var_dump(ssh2_sftp_symlink($sftp, $filename, $linkname));
var_dump(ssh2_sftp_readlink($sftp, $linkname) == $filename);
$stat =  ssh2_sftp_stat ($sftp, $filename);
var_dump(ssh2_sftp_rmdir($sftp, $filename));
var_dump(ssh2_sftp_unlink($sftp, $linkname));
var_dump(($stat['mode'] & 040000) == 040000); // is_dir()
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
