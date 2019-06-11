<?php

namespace Swoole;

class StringObject
{
    /**
     * @var string
     */
    protected $string;

    /**
     * StringObject constructor.
     * @param $string
     */
    public function __construct(string $string = '')
    {
        $this->string = $string;
    }

    /**
     * @return int
     */
    public function length(): int
    {
        return strlen($this->string);
    }

    /**
     * @param string $needle
     * @param int $offset
     * @return bool|int
     */
    public function indexOf(string $needle, int $offset = 0)
    {
        return strpos($this->string, $needle, $offset);
    }

    /**
     * @param string $needle
     * @param int $offset
     * @return bool|int
     */
    public function lastIndexOf(string $needle, int $offset = 0)
    {
        return strrpos($this->string, $needle, $offset);
    }

    /**
     * @param string $needle
     * @param int $offset
     * @return bool|int
     */
    public function pos(string $needle, int $offset = 0)
    {
        return strpos($this->string, $needle, $offset);
    }

    /**
     * @param string $needle
     * @param int $offset
     * @return bool|int
     */
    public function rpos(string $needle, int $offset = 0)
    {
        return strrpos($this->string, $needle, $offset);
    }

    /**
     * @param string $needle
     * @return bool|int
     */
    public function ipos(string $needle)
    {
        return stripos($this->string, $needle);
    }

    /**
     * @return static
     */
    public function lower(): self
    {
        return new static(strtolower($this->string));
    }

    /**
     * @return static
     */
    public function upper(): self
    {
        return new static(strtoupper($this->string));
    }

    /**
     * @return static
     */
    public function trim(): self
    {
        return new static(trim($this->string));
    }

    /**
     * @return static
     */
    public function lrim(): self
    {
        return new static(ltrim($this->string));
    }

    /**
     * @return static
     */
    public function rtrim(): self
    {
        return new static(rtrim($this->string));
    }

    /**
     * @param int $offset
     * @param mixed ...$length
     * @return static
     */
    public function substr(int $offset, ...$length): self
    {
        return new static(substr($this->string, $offset, ...$length));
    }

    /**
     * @param $n
     * @return StringObject
     */
    public function repeat($n)
    {
        return new static(str_repeat($this->string, $n));
    }

    /**
     * @param string $search
     * @param string $replace
     * @param null $count
     * @return static
     */
    public function replace(string $search, string $replace, &$count = null): self
    {
        return new static(str_replace($search, $replace, $this->string, $count));
    }

    /**
     * @param string $needle
     * @return bool
     */
    public function startsWith(string $needle): bool
    {
        return strpos($this->string, $needle) === 0;
    }

    /**
     * @param string $subString
     * @return bool
     */
    public function contains(string $subString): bool
    {
        return strpos($this->string, $subString) !== false;
    }

    /**
     * @param string $needle
     * @return bool
     */
    public function endsWith(string $needle): bool
    {
        return strrpos($this->string, $needle) === (strlen($needle) - 1);
    }

    /**
     * @param string $delimiter
     * @param int $limit
     * @return ArrayObject
     */
    public function split(string $delimiter, int $limit = PHP_INT_MAX): ArrayObject
    {
        return static::detectArrayType(explode($delimiter, $this->string, $limit));
    }

    /**
     * @param int $index
     * @return string
     */
    public function char(int $index): string
    {
        return $this->string[$index];
    }

    /**
     * @param int $chunkLength
     * @param string $chunkEnd
     * @return static
     */
    public function chunkSplit(int $chunkLength = 1, string $chunkEnd = ''): self
    {
        return new static(chunk_split($this->string, $chunkLength, $chunkEnd));
    }

    /**
     * @param int $splitLength
     * @return ArrayObject
     */
    public function chunk($splitLength = 1): ArrayObject
    {
        return static::detectArrayType(str_split($this->string, $splitLength));
    }

    /**
     * @return string
     */
    public function toString()
    {
        return $this->string;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->string;
    }

    /**
     * @param array $value
     * @return ArrayObject
     */
    protected static function detectArrayType(array $value): ArrayObject
    {
        return new ArrayObject($value);
    }
}
