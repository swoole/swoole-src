--TEST--
swoole_http_cookie: subclass without parent constructor
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class BadCookie extends Swoole\Http\Cookie {
    public function __construct() {
    }
}

$cookie = new BadCookie();
Assert::false($cookie->toString());
$cookie->reset();
Assert::same(swoole_last_error(), SWOOLE_ERROR_HTTP_COOKIE_UNAVAILABLE);

try {
    $cookie->withName('foo');
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}
?>
--EXPECT--
Swoole\Http\Cookie is not initialized
