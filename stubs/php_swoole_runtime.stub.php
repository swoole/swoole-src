<?php
/**
 * @strict-properties
 */
namespace Swoole {
	class Runtime {
		public function enableCoroutine(bool $enable = true, int $flags = SWOOLE_HOOK_ALL): bool {}
		public function getHookFlags(): int {}
		public function setHookFlags(int $flags = SWOOLE_HOOK_ALL): bool {}

		public static function enableCoroutine(bool $enable = true, int $flags = SWOOLE_HOOK_ALL): bool {}
		public static function getHookFlags(): int {}
		public static function setHookFlags(int $flags = SWOOLE_HOOK_ALL): bool {}
	}
}
