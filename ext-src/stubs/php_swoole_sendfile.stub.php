<?php

namespace Swoole {
    final class SendFile {
        public readonly string $filename;
        public int $offset = 0;
        public int $length = 0;
        public bool $deleteAfterSend = false;

        public function __construct(string $filename) {}
    }
}
