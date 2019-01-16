--TEST--
swoole_mmap: base
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($n = MAX_REQUESTS; $n--;) {
    $randoms[] = get_safe_random();
}
$randoms_s = implode('', $randoms);
$filename = __DIR__ . '/test.file';
file_put_contents($filename, str_repeat("\n", strlen($randoms_s)));
register_shutdown_function(function () use ($filename) {
    @unlink($filename);
});
$fp = Swoole\Mmap::open($filename);
foreach ($randoms as $random) {
    assert(fwrite($fp, $random) === strlen($random));
}
$fp = null;
assert(strncmp(file_get_contents($filename), $randoms_s, strlen($randoms_s)) === 0);
$fp = Swoole\Mmap::open($filename);
assert(fseek($fp, 0, SEEK_SET) === 0);
assert(fseek($fp, -1, SEEK_SET) === -1);
assert(fread($fp, strlen($randoms_s)) === $randoms_s);
assert(fseek($fp, strlen($randoms[0]), SEEK_SET) === 0);
assert(fread($fp, strlen($randoms[1])) === $randoms[1]);
assert(fseek($fp, strlen($randoms[2]), SEEK_CUR) === 0);
assert(fread($fp, strlen($randoms[3])) === $randoms[3]);
assert(fseek($fp, 1, SEEK_END) === -1);
assert(fseek($fp, -(strlen($randoms_s) + 1), SEEK_END) === -1);
assert(fread($fp, strlen($randoms[0])) === '');
assert(fseek($fp, -strlen($randoms_s), SEEK_END) === 0);
assert(fread($fp, strlen($randoms[0])) === $randoms[0]);
assert(fseek($fp, -1, SEEK_END) === 0);
assert(fread($fp, 1) === substr($randoms_s, -1, 1));
echo "DONE\n";
?>
--EXPECT--
DONE
