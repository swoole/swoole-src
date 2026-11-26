--TEST--
swoole_server: validate isolation settings before starting workers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_extension_not_exist('posix');
$account = posix_getpwuid(0);
skip('requires a resolvable root account and group', !$account || !posix_getgrgid($account['gid']));
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Server;
use SwooleTest\Assert;

$account = posix_getpwuid(0);
$user = $account['name'];
$group = posix_getgrgid($account['gid'])['name'];
$directory = sys_get_temp_dir();
$file = tmpfile();
Assert::resource($file);
$filePath = stream_get_meta_data($file)['uri'];

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);
Assert::true($server->set(['user' => $user, 'worker_num' => 1]));
Assert::true($server->set(['group' => $group]));
Assert::true($server->set(['chroot' => $directory]));
$valid = $server->setting;

$empty = ['user' => '', 'group' => '', 'chroot' => ''];
$missingAccount = 'swoole-missing-' . bin2hex(random_bytes(6));
foreach ([
    ['user', $missingAccount, $missingAccount],
    ['group', $missingAccount, $missingAccount],
    ['chroot', $filePath . '.missing', 'cannot access chroot'],
    ['chroot', $filePath, 'is not a directory'],
    ['user', $user . "\0extra", 'must not contain null bytes'],
    ['group', $group . "\0extra", 'must not contain null bytes'],
    ['chroot', $directory . "\0extra", 'must not contain null bytes'],
] as [$option, $value, $message]) {
    try {
        $server->set([$option => $value, 'worker_num' => 2] + $empty);
        throw new RuntimeException("Invalid $option was accepted");
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::contains($exception->getMessage(), $option);
        Assert::contains($exception->getMessage(), $message);
        Assert::same($server->setting, $valid);
    }
}

Assert::true($server->set($empty));
Assert::same(array_intersect_key($server->setting, $empty), $empty);
fclose($file);
echo "DONE\n";
?>
--EXPECT--
DONE
