--TEST--
swoole_coroutine_system: getaddrinfo timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_not_root();
skip_if_in_ci();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$tmpdir = '/tmp/' . uniqid();

mkdir_if_not_exists($tmpdir . '/etc');
chroot($tmpdir);
if (!is_file('/etc/resolv.conf')) {
    file_put_contents('/etc/resolv.conf', "nameserver 192.168.8.8\noptions timeout:1 retry:1\n");
}

Co\run(static function () {
    $res = Swoole\Coroutine\System::getaddrinfo(
        domain: 'swoole-non-existent-domain',
        protocol: 0,
        service: '',
        timeout: 0.5,
    );
    Assert::false($res);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_TIMEDOUT);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
