<?php

namespace Swoole;

use ArrayAccess;
use Countable;
use Iterator;
use RuntimeException;
use Serializable;

class ArrayObject implements ArrayAccess, Serializable, Countable, Iterator
{
    /**
     * @var array
     */
    protected $array;

    /**
     * ArrayObject constructor.
     * @param array $array
     */
    public function __construct(array $array = [])
    {
        $this->array = $array;
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return empty($this->array);
    }

    /**
     * @return int
     */
    public function count(): int
    {
        return count($this->array);
    }

    /**
     * @return mixed
     */
    public function current()
    {
        return current($this->array);
    }

    /**
     * @return mixed
     */
    public function key()
    {
        return key($this->array);
    }

    /**
     * @return bool
     */
    public function valid(): bool
    {
        return array_key_exists($this->key(), $this->array);
    }

    /**
     * @return mixed
     */
    public function rewind()
    {
        return reset($this->array);
    }

    /**
     * @return mixed
     */
    public function next()
    {
        return next($this->array);
    }

    /**
     * @param $key
     * @return ArrayObject|StringObject|mixed
     */
    public function get($key)
    {
        return static::detectType($this->array[$key]);
    }

    /**
     * @param $key
     * @param $value
     * @return $this
     */
    public function set($key, $value): self
    {
        $this->array[$key] = $value;
        return $this;
    }

    /**
     * @param $key
     * @return $this
     */
    public function delete($key): self
    {
        unset($this->array[$key]);
        return $this;
    }

    /**
     * @param $value
     * @param bool $strict
     * @param bool $loop
     * @return $this
     */
    public function remove($value, bool $strict = true, bool $loop = false): self
    {
        do {
            $key = $this->search($value, $strict);
            if ($key) {
                unset($this->array[$key]);
            } else {
                break;
            }
        } while ($loop);
        return $this;
    }

    /**
     * @return $this
     */
    public function clear(): self
    {
        $this->array = [];
        return $this;
    }

    /**
     * @param mixed $key
     * @return mixed|null
     */
    public function offsetGet($key)
    {
        if (!array_key_exists($key, $this->array)) {
            return null;
        }
        return $this->array[$key];
    }

    /**
     * @param mixed $key
     * @param mixed $value
     */
    public function offsetSet($key, $value)
    {
        $this->array[$key] = $value;
    }

    /**
     * @param mixed $key
     */
    public function offsetUnset($key)
    {
        unset($this->array[$key]);
    }

    /**
     * @param mixed $key
     * @return bool
     */
    public function offsetExists($key)
    {
        return isset($this->array[$key]);
    }

    /**
     * @param $key
     * @return bool
     */
    public function exists($key): bool
    {
        return array_key_exists($key, $this->array);
    }

    /**
     * @param $value
     * @param bool $strict
     * @return bool
     */
    public function contains($value, bool $strict = true): bool
    {
        return in_array($value, $this->array, $strict);
    }

    /**
     * @param $value
     * @param bool $strict
     * @return mixed
     */
    public function indexOf($value, bool $strict = true)
    {
        return $this->search($value, $strict);
    }

    /**
     * @param $value
     * @param bool $strict
     * @return mixed
     */
    public function lastIndexOf($value, bool $strict = true)
    {
        $array = $this->array;
        for (end($array); ($currentKey = key($array)) !== null; prev($array)) {
            $currentValue = current($array);
            if ($currentValue == $value) {
                if ($strict && $currentValue !== $value) {
                    continue;
                }
                break;
            }
        }
        return $currentKey;
    }

    /**
     * @param $needle
     * @param $strict
     * @return mixed
     */
    public function search($needle, $strict = true)
    {
        return array_search($needle, $this->array, $strict);
    }

    /**
     * @param string $glue
     * @return StringObject
     */
    public function join(string $glue = ''): StringObject
    {
        return static::detectStringType(implode($glue, $this->array));
    }

    /**
     * @return StringObject
     */
    public function serialize(): StringObject
    {
        return static::detectStringType(serialize($this->array));
    }

    /**
     * @param string $string
     * @return $this
     */
    public function unserialize($string): self
    {
        $this->array = (array)unserialize($string);
        return $this;
    }

    /**
     * @return float|int
     */
    public function sum()
    {
        return array_sum($this->array);
    }

    /**
     * @return float|int
     */
    public function product()
    {
        return array_product($this->array);
    }

    /**
     * @param $value
     * @return int
     */
    public function push($value)
    {
        return array_push($this->array, $value);
    }

    /**
     * @param $value
     * @return int
     */
    public function pushBack($value)
    {
        return array_unshift($this->array, $value);
    }

    /**
     * @param int $offset
     * @param $value
     * @return $this
     */
    public function insert(int $offset, $value): self
    {
        if (is_array($value) || is_object($value) || is_null($value)) {
            $value = [$value];
        }
        array_splice($this->array, $offset, 0, $value);
        return $this;
    }

    /**
     * @return mixed
     */
    public function pop()
    {
        return array_pop($this->array);
    }

    /**
     * @return mixed
     */
    public function popFront()
    {
        return array_shift($this->array);
    }

    /**
     * @param $offset
     * @param int $length
     * @param bool $preserve_keys
     * @return static
     */
    public function slice($offset, int $length = null, bool $preserve_keys = false): self
    {
        return new static(array_slice($this->array, ...func_get_args()));
    }

    /**
     * @return ArrayObject|StringObject|mixed
     */
    public function randomGet()
    {
        return static::detectType($this->array[array_rand($this->array, 1)]);
    }

    /**
     * @param $fn callable
     * @return $this
     */
    public function each(callable $fn): self
    {
        if (array_walk($this->array, $fn) === false) {
            throw new RuntimeException('array_walk() failed');
        }
        return $this;
    }

    /**
     * @param $fn callable
     * @return static
     */
    public function map(callable $fn): self
    {
        return new static(array_map($fn, $this->array));
    }

    /**
     * @param $fn callable
     * @return mixed
     */
    public function reduce(callable $fn)
    {
        return array_reduce($this->array, $fn);
    }

    /**
     * @param int $search_value
     * @param bool $strict
     * @return static
     */
    public function keys(int $search_value = null, $strict = false): self
    {
        return new static(array_keys($this->array, $search_value, $strict));
    }

    /**
     * @return static
     */
    public function values(): self
    {
        return new static(array_values($this->array));
    }

    /**
     * @param $column_key
     * @param mixed ...$index
     * @return static
     */
    public function column($column_key, ...$index): self
    {
        return new static(array_column($this->array, $column_key, ...$index));
    }

    /**
     * @param int $sort_flags
     * @return static
     */
    public function unique(int $sort_flags = SORT_STRING): self
    {
        return new static(array_unique($this->array, $sort_flags));
    }

    /**
     * @param bool $preserve_keys
     * @return static
     */
    public function reverse(bool $preserve_keys = false): self
    {
        return new static(array_reverse($this->array, $preserve_keys));
    }

    /**
     * @param int $size
     * @param bool $preserve_keys
     * @return static
     */
    public function chunk(int $size, bool $preserve_keys = false): self
    {
        return new static(array_chunk($this->array, $size, $preserve_keys));
    }

    /**
     * Swap keys and values in an array
     * @return static
     */
    public function flip(): self
    {
        return new static(array_flip($this->array));
    }

    /**
     * @param $fn callable
     * @param int $flag
     * @return static
     */
    public function filter(callable $fn, int $flag = 0): self
    {
        return new static(array_filter($this->array, $fn, $flag));
    }

    /**
     * | Function name     | Sorts by | Maintains key association   | Order of sort               | Related functions |
     * | :---------------- | :------- | :-------------------------- | :-------------------------- | :---------------- |
     * | array_multisort() | value    | associative yes, numeric no | first array or sort options | array_walk()      |
     * | asort()           | value    | yes                         | low to high                 | arsort()          |
     * | arsort()          | value    | yes                         | high to low                 | asort()           |
     * | krsort()          | key      | yes                         | high to low                 | ksort()           |
     * | ksort()           | key      | yes                         | low to high                 | asort()           |
     * | natcasesort()     | value    | yes                         | natural, case insensitive   | natsort()         |
     * | natsort()         | value    | yes                         | natural                     | natcasesort()     |
     * | rsort()           | value    | no                          | high to low                 | sort()            |
     * | shuffle()         | value    | no                          | random                      | array_rand()      |
     * | sort()            | value    | no                          | low to high                 | rsort()           |
     * | uasort()          | value    | yes                         | user defined                | uksort()          |
     * | uksort()          | key      | yes                         | user defined                | uasort()          |
     * | usort()           | value    | no                          | user defined                | uasort()          |
     */

    /**
     * @param int $sort_order
     * @param int $sort_flags
     * @return $this
     */
    public function multiSort(int $sort_order = SORT_ASC, int $sort_flags = SORT_REGULAR): self
    {
        if (array_multisort($this->array, $sort_order, $sort_flags) !== true) {
            throw new RuntimeException('array_multisort() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function asort(int $sort_flags = SORT_REGULAR): self
    {
        if (asort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('asort() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function arsort(int $sort_flags = SORT_REGULAR): self
    {
        if (arsort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('arsort() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function krsort(int $sort_flags = SORT_REGULAR): self
    {
        if (krsort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('krsort() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function ksort(int $sort_flags = SORT_REGULAR): self
    {
        if (ksort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('ksort() failed');
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function natcasesort(): self
    {
        if (natcasesort($this->array) !== true) {
            throw new RuntimeException('natcasesort() failed');
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function natsort(): self
    {
        if (natsort($this->array) !== true) {
            throw new RuntimeException('natsort() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function rsort(int $sort_flags = SORT_REGULAR): self
    {
        if (rsort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('rsort() failed');
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function shuffle(): self
    {
        if (shuffle($this->array) !== true) {
            throw new RuntimeException('shuffle() failed');
        }
        return $this;
    }

    /**
     * @param int $sort_flags
     * @return $this
     */
    public function sort(int $sort_flags = SORT_REGULAR): self
    {
        if (sort($this->array, $sort_flags) !== true) {
            throw new RuntimeException('sort() failed');
        }
        return $this;
    }

    /**
     * @param callable $value_compare_func
     * @return $this
     */
    public function uasort(callable $value_compare_func): self
    {
        if (uasort($this->array, $value_compare_func) !== true) {
            throw new RuntimeException('uasort() failed');
        }
        return $this;
    }

    /**
     * @param callable $value_compare_func
     * @return $this
     */
    public function uksort(callable $value_compare_func): self
    {
        if (uksort($this->array, $value_compare_func) !== true) {
            throw new RuntimeException('uksort() failed');
        }
        return $this;
    }

    /**
     * @param callable $value_compare_func
     * @return $this
     */
    public function usort(callable $value_compare_func): self
    {
        if (usort($this->array, $value_compare_func) !== true) {
            throw new RuntimeException('usort() failed');
        }
        return $this;
    }

    /**
     * @return array
     */
    public function __toArray(): array
    {
        return $this->array;
    }

    /**
     * @param $value
     * @return ArrayObject|StringObject|mixed
     */
    protected static function detectType($value)
    {
        if (is_string($value)) {
            return static::detectStringType($value);
        } elseif (is_array($value)) {
            return static::detectArrayType($value);
        } else {
            return $value;
        }
    }

    /**
     * @param string $value
     * @return StringObject
     */
    protected static function detectStringType(string $value): StringObject
    {
        return new StringObject($value);
    }

    /**
     * @param array $value
     * @return static
     */
    protected static function detectArrayType(array $value): self
    {
        return new static($value);
    }
}
