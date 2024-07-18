<?php
namespace Swoole\Http {
	class Cookie {
	    public function __construct() {}
	    public function setName(string $name): \Swoole\Http\Cookie {}
	    public function setValue(string $value = '', bool $encode = true): \Swoole\Http\Cookie {}
	    public function setExpires(int $expires = 0): \Swoole\Http\Cookie {}
	    public function setPath(string $path = '/'): \Swoole\Http\Cookie {}
	    public function setDomain(string $domain = ''): \Swoole\Http\Cookie {}
	    public function setSecure(bool $secure = false): \Swoole\Http\Cookie {}
	    public function setHttpOnly(bool $httpOnly = false): \Swoole\Http\Cookie {}
	    public function setSameSite(string $sameSite = ''): \Swoole\Http\Cookie {}
	    public function setPriority(string $priority = ''): \Swoole\Http\Cookie {}
	    public function setPartitioned(bool $partitioned = false): \Swoole\Http\Cookie {}
	    public function getCookie(): array {}
	    public function reset(): bool {}
	}
}
