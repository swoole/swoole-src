<?php
namespace Swoole {
	class Runtime {
		public static function enableCoroutine(int $flags = SWOOLE_HOOK_ALL): bool {}
		public static function getHookFlags(): int {}
		public static function setHookFlags(int $flags): bool {}
	}
}
