--TEST--
ssh2_stream_select() - Tests opening a shell and using stream_select
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));
$shell = ssh2_shell($ssh);
var_dump($shell);

fwrite($shell, "echo \"howdy\"\n");
sleep(1);

$read = [$shell];
$write = null;
$except = null;
$timeout = 5;
$start = time();
if (stream_select($read, $write, $except, $timeout) !== false && count($read) > 0) {
	while($line = fgets($shell)) {
	    echo $line;
	}
}
$elapsed = time() - $start;
var_dump(($elapsed < $timeout));

--EXPECTF--
bool(true)
resource(%d) of type (stream)
%a
%a
%a
howdy
%sbool(true)