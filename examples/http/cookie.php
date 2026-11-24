<?php
// Build a Set-Cookie header value with Swoole\Http\Cookie.
// Run: php examples/http/cookie.php
$cookie = new Swoole\Http\Cookie();
$cookie->withName('session');
$cookie->withValue('abc123');
$cookie->withExpires(time() + 3600);
$cookie->withPath('/');
$cookie->withHttpOnly(true);
echo $cookie->toString(), PHP_EOL;
