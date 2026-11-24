--TEST--
swoole_http_server: failed Cookie serialization preserves configuration for retry
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$expected = 'token=a+b; path=/path; domain=example.com; secure; HttpOnly; SameSite=Lax; Priority=High; Partitioned';
foreach ([
    ['withName', 'bad name', 'token'],
    ['withValue', "bad\nvalue", 'a+b'],
    ['withPath', "/bad\npath", '/path'],
    ['withDomain', 'bad;domain', 'example.com'],
    ['withExpires', 253402300800, 0],
] as [$method, $invalid, $valid]) {
    $cookie = (new Swoole\Http\Cookie(false))
        ->withName('token')->withValue('a+b')->withPath('/path')->withDomain('example.com')
        ->withSecure(true)->withHttpOnly(true)->withSameSite('Lax')->withPriority('High')->withPartitioned(true);
    $cookie->$method($invalid);
    Assert::false(@$cookie->toString());
    Assert::false(@$cookie->toString());
    $cookie->$method($valid);
    Assert::same($cookie->toString(), $expected);
    Assert::same($cookie->toString(), $expected);

    $cookie->reset();
    Assert::false(@$cookie->toString());
    $cookie->withName('reset')->withValue('a+b');
    Assert::same($cookie->toString(), 'reset=a%2Bb');
}
echo "DONE\n";
?>
--EXPECT--
DONE
