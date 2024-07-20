<?php
namespace Swoole\Http {
	class Cookie {
	    public function __construct() {}
	    public function withName(string $name): \Swoole\Http\Cookie {}
	    public function withValue(string $value = '', bool $encode = true): \Swoole\Http\Cookie {}
	    public function withExpires(int $expires = 0): \Swoole\Http\Cookie {}
	    public function withPath(string $path = '/'): \Swoole\Http\Cookie {}
	    public function withDomain(string $domain = ''): \Swoole\Http\Cookie {}
	    public function withSecure(bool $secure = false): \Swoole\Http\Cookie {}
	    public function withHttpOnly(bool $httpOnly = false): \Swoole\Http\Cookie {}
	    public function withSameSite(string $sameSite = ''): \Swoole\Http\Cookie {}
	    public function withPriority(string $priority = ''): \Swoole\Http\Cookie {}
	    public function withPartitioned(bool $partitioned = false): \Swoole\Http\Cookie {}
	    public function getCookie(): array {}
	    public function reset(): bool {}
	}
}
