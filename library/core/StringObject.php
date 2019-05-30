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
     * @return StringObject
     */
    public function substr(int $offset, ...$length): self
    {
        return new static(substr($this->string, $offset, ...$length));
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
        return $this->pos($needle) === 0;
    }

    /**
     * @param string $subString
     * @return bool
     */
    public function contains(string $subString): bool
    {
        return $this->pos($subString) !== false;
    }

    /**
     * @param string $needle
     * @return bool
     */
    public function endsWith(string $needle): bool
    {
        $length = strlen($needle);
        if ($length == 0) {
            return true;
        }
        return substr($this->string, -$length) === $needle;
    }

    /**
     * @param string $delimiter
     * @param int $limit
     * @return ArrayObject
     */
    public function split(string $delimiter, int $limit = PHP_INT_MAX): ArrayObject
    {
        return new ArrayObject(explode($delimiter, $this->string, $limit));
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
     * @return StringObject
     */
    public function chunkSplit(int $chunkLength = 1, string $chunkEnd = ''): StringObject
    {
        return new static(chunk_split($this->string, $chunkLength, $chunkEnd));
    }

    /**
     * @param int $splitLength
     * @return ArrayObject
     */
    public function chunk($splitLength = 1)
    {
        return new ArrayObject(str_split($this->string, $splitLength));
    }

    /**
     * @param int $depth
     * @param int $options
     * @return mixed
     */
    public function jsonDecode(int $depth = 512, int $options = 0)
    {
        return new ArrayObject(json_decode($this->string, true, $depth, $options));
    }

    /**
     * @param string $pattern
     * @param int $flags
     * @param int $offset
     * @param null $count
     * @return mixed
     */
    public function pregMatch(string $pattern, $flags = 0, $offset = 0, &$count = null)
    {
        $count = preg_match($pattern, $this->string, $matches, $flags, $offset);
        return $matches;
    }

    /**
     * @param string $pattern
     * @param int $flags
     * @param int $offset
     * @param null $count
     * @return mixed
     */
    public function pregMatchAll(string $pattern, $flags = 0, $offset = 0, &$count = null)
    {
        $count = preg_match_all($pattern, $this->string, $matches, $flags, $offset);
        return $matches;
    }

    /**
     * @param string $pattern
     * @param string $replacement
     * @param int $limit
     * @param null $count
     * @return string
     */
    public function pregReplace(string $pattern, string $replacement, int $limit = -1, &$count = null): string
    {
        return preg_replace($pattern, $replacement, $this->string, $limit, $count);
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->string;
    }
}
