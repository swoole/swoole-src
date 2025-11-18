--TEST--
Bug #63480 (Warning on using the SSH2 Session resource in the uri)
--SKIPIF--
<?php
require('ssh2_skip.inc');
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
ssh2t_auth($ssh);

$filename = ssh2t_tempnam();
file_put_contents("ssh2.sftp://$ssh/$filename", "yada yada");

readfile("ssh2.sftp://$ssh/$filename");

unlink("ssh2.sftp://$ssh/$filename");
?>
--EXPECT--
yada yada
