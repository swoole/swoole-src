--TEST--
ssh2_shell_test() - Tests opening a shell
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php require_once 'ssh2_test.inc';

use Swoole\Timer;
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($ssh));
    $shell = ssh2_shell($ssh);
    var_dump($shell);
    $greet = fread($shell, 8192);
    sleep(1);
    fwrite($shell, 'echo "foo bar"' . PHP_EOL);
    $cid = Co::getCid();
    Timer::after(1000, function () use ($cid) {
        Co::cancel($cid, true);
    });
    try {
        while ($line = fgets($shell)) {
            echo $line;
        }
    } catch (Swoole\Coroutine\CanceledException $e) {
        echo "DONE\n";
    }
});
?>
--EXPECTF--
bool(true)
resource(%d) of type (stream)
%a
%a
