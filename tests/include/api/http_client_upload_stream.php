<?php

class HttpClientUploadStream
{
    public $context;
    private object $state;
    private static array $pending = [];

    public static function open(int $length, bool $knownLength = true, bool $seekable = true): array
    {
        if (!in_array('http-client-upload', stream_get_wrappers(), true)) {
            Assert::true(stream_wrapper_register('http-client-upload', self::class));
        }
        $state = (object) [
            'length' => $length,
            'available' => $length,
            'position' => 0,
            'knownLength' => $knownLength,
            'seekable' => $seekable,
            'fragment' => 65536,
            'reads' => 0,
            'maxRead' => 0,
            'rewinds' => 0,
            'closed' => false,
            'onRead' => null,
            'onStat' => null,
        ];
        $key = (string) spl_object_id($state);
        self::$pending[$key] = $state;
        $stream = fopen('http-client-upload://' . $key, 'rb');
        Assert::true(is_resource($stream));
        stream_set_chunk_size($stream, 65536);
        return [$stream, $state];
    }

    public static function bytes(int $position, int $length): string
    {
        $pattern = "01234567\0\xff";
        $offset = $position % strlen($pattern);
        return substr(str_repeat($pattern, intdiv($offset + $length + strlen($pattern) - 1, strlen($pattern))), $offset, $length);
    }

    public function stream_open($path, $mode, $options, &$openedPath): bool
    {
        $key = substr($path, strlen('http-client-upload://'));
        $this->state = self::$pending[$key];
        unset(self::$pending[$key]);
        return true;
    }

    public function stream_read($count): string
    {
        $state = $this->state;
        $state->reads++;
        $state->maxRead = max($state->maxRead, $count);
        if ($state->onRead !== null) {
            ($state->onRead)($state);
        }
        $length = min($count, $state->fragment, max(0, $state->available - $state->position));
        $data = self::bytes($state->position, $length);
        $state->position += $length;
        return $data;
    }

    public function stream_eof(): bool
    {
        return $this->state->position >= $this->state->available;
    }

    public function stream_tell(): int
    {
        return $this->state->position;
    }

    public function stream_seek($offset, $whence): bool
    {
        if (!$this->state->seekable) {
            return false;
        }
        if ($whence === SEEK_CUR) {
            $offset += $this->state->position;
        } elseif ($whence === SEEK_END) {
            $offset += $this->state->length;
        }
        if ($offset < 0) {
            return false;
        }
        if ($offset < $this->state->position) {
            $this->state->rewinds++;
        }
        $this->state->position = $offset;
        return true;
    }

    public function stream_stat(): array|false
    {
        if ($this->state->onStat !== null) {
            ($this->state->onStat)($this->state);
        }
        return $this->state->knownLength ? ['mode' => 0100000 | 0400, 'size' => $this->state->length] : false;
    }

    public function stream_close(): void
    {
        $this->state->closed = true;
    }
}
