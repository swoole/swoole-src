<?php
namespace Swoole {
	class Runtime {
		public static function enableCoroutine(bool|int $enable = SWOOLE_HOOK_ALL, int $flags = SWOOLE_HOOK_ALL): bool {}
		public static function getHookFlags(): int {}
		public static function setHookFlags(int $flags): bool {}
	}
}
