<?php
namespace Swoole\Http {
	class Cookie {
	    public function __construct() {}
	    public function setName(string $name): void {}
	    public function setValue(string $value = ''): void {}
	    public function setExpires(int $expires = 0): void {}
	    public function setPath(string $path = '/'): void {}
	    public function setDomain(string $domain = ''): void {}
	    public function setSecure(bool $secure = false): void {}
	    public function setHttpOnly(bool $httpOnly = false): void {}
	    public function setSameSite(string $sameSite = ''): void {}
	    public function setPriority(string $priority = ''): void {}
	    public function setPartitioned(bool $partitioned = false): void {}
	    public function getCookie(): array {}
	    public function reset(): bool {}
	}
}
