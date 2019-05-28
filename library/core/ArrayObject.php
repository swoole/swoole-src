<?php
namespace Swoole;

class ArrayObject implements \ArrayAccess, \Serializable, \Countable, \Iterator
{
    protected $array;

    function __construct($array = array())
    {
        $this->array = $array;
    }

    function current()
    {
        return current($this->array);
    }

    function key()
    {
        return key($this->array);
    }

    function valid()
    {
        return array_key_exists($this->key(), $this->array);
    }

    function rewind()
    {
        return reset($this->array);
    }

    function next()
    {
        return next($this->array);
    }

    function serialize()
    {
        return serialize($this->array);
    }

    /**
     * @return StringObject
     */
    function json()
    {
        return new StringObject(json_encode($this->array));
    }

    function indexOf($value)
    {
        return $this->search($value);
    }

    function lastIndexOf($value)
    {
        $find = false;
        foreach ($this->array as $k => $v)
        {
            if ($value == $v)
            {
                $find = $k;
            }
        }

        return $find;
    }

    function unserialize($str)
    {
        $this->array = unserialize($str);
    }

    function __get($key)
    {
        return $this->array[$key];
    }

    function __set($key, $value)
    {
        $this->array[$key] = $value;
    }

    function set($key, $value)
    {
        $this->array[$key] = $value;
    }

    /**
     * @param $key
     * @return ArrayObject|StringObject
     */
    function get($key)
    {
        return self::detectType($this->array[$key]);
    }

    function delete($key)
    {
        if (isset($this->array[$key]))
        {
            return false;
        }
        else
        {
            unset($this->array[$key]);

            return true;
        }
    }

    function clear()
    {
        $this->array = array();
    }

    /**
     * @param mixed $k
     * @return mixed|null
     */
    function offsetGet($k)
    {
        if (!array_key_exists($k, $this->array))
        {
            return null;
        }
        return $this->array[$k];
    }

    /**
     * @param mixed $k
     * @param mixed $v
     */
    function offsetSet($k, $v)
    {
        $this->array[$k] = $v;
    }

    /**
     * @param mixed $k
     */
    function offsetUnset($k)
    {
        unset($this->array[$k]);
    }

    /**
     * @param mixed $k
     * @return bool
     */
    function offsetExists($k)
    {
        return isset($this->array[$k]);
    }

    /**
     * @param $val
     * @return bool
     */
    function contains($val)
    {
        return in_array($val, $this->array);
    }

    /**
     * @param $key
     * @return bool
     */
    function exists($key)
    {
        return array_key_exists($key, $this->array);
    }

    /**
     * @param $str
     * @return StringObject
     */
    function join($str)
    {
        return new StringObject(implode($str, $this->array));
    }

    /**
     * @param $offset
     * @param $val
     * @return bool|ArrayObject
     */
    function insert($offset, $val)
    {
        if ($offset > count($this->array))
        {
            return false;
        }
        return new ArrayObject(array_splice($this->array, $offset, 0, $val));
    }

    /**
     * @param $find
     * @param $strict
     * @return mixed
     */
    function search($find, $strict = false)
    {
        return array_search($find, $this->array, $strict);
    }

    /**
     * @return int
     */
    function count()
    {
        return count($this->array);
    }

    /**
     * @return bool
     */
    function isEmpty()
    {
        return empty($this->array);
    }


    /**
     * @return float|int
     */
    function sum()
    {
        return array_sum($this->array);
    }

    /**
     * @return float|int
     */
    function product()
    {
        return array_product($this->array);
    }

    /**
     * @param $val
     * @return int
     */
    function append($val)
    {
        return array_push($this->array, $val);
    }

    /**
     * @param $val
     * @return int
     */
    function prepend($val)
    {
        return array_unshift($this->array, $val);
    }

    /**
     * @return mixed
     */
    function pop()
    {
        return array_pop($this->array);
    }

    /**
     * @return mixed
     */
    function shift()
    {
        return array_shift($this->array);
    }

    /**
     * @param $offset
     * @param $length
     * @return ArrayObject
     */
    function slice($offset, $length = null)
    {
        return new ArrayObject(array_slice($this->array, $offset, $length));
    }

    /**
     * @return mixed
     */
    function randGet()
    {
        return self::detectType($this->array[array_rand($this->array, 1)]);
    }

    /**
     * @param $value
     * @return ArrayObject
     */
    function remove($value)
    {
        $key = $this->search($value);
        if ($key)
        {
            unset($this->array[$key]);
        }

        return $this;
    }

    /**
     * @param $fn callable
     * @return ArrayObject
     */
    function each(callable $fn)
    {
        if (array_walk($this->array, $fn) === false)
        {
            throw new \RuntimeException("array_walk() failed.");
        }

        return $this;
    }

    /**
     * @param $fn callable
     * @return ArrayObject
     */
    function map(callable $fn)
    {
        return new ArrayObject(array_map($fn, $this->array));
    }

    /**
     * @param $fn callable
     * @return mixed
     */
    function reduce(callable $fn)
    {
        return array_reduce($this->array, $fn);
    }

    /**
     *  @return ArrayObject
     */
    function values()
    {
        return new ArrayObject(array_values($this->array));
    }

    /**
     * @param $column_key
     * @param null $index
     * @return array|ArrayObject
     */
    function column($column_key, $index = null)
    {
        if ($index)
        {
            return array_column($this->array, $column_key, $index);
        }
        else
        {
            return new ArrayObject(array_column($this->array, $column_key));
        }
    }

    /**
     * @param null $search_value
     * @param bool $strict
     * @return ArrayObject
     */
    function keys($search_value = null, $strict = false)
    {
        return new ArrayObject(array_keys($this->array, $search_value, $strict));
    }

    /**
     * @param int $sort_flags
     * @return ArrayObject
     */
    function unique($sort_flags = SORT_STRING)
    {
        return new ArrayObject(array_unique($this->array, $sort_flags));
    }

    /**
     * @param int $sort_flags
     * @return ArrayObject
     */
    function sort($sort_flags = SORT_REGULAR)
    {
        $newArray = $this->array;
        sort($newArray, $sort_flags);

        return new ArrayObject($newArray);
    }

    /**
     * @param bool $preserve_keys
     * @return ArrayObject
     */
    function reverse($preserve_keys = false)
    {
        return new ArrayObject(array_reverse($this->array, $preserve_keys));
    }

    /**
     * @return ArrayObject
     */
    function shuffle()
    {
        if (shuffle($this->array) === false)
        {
            throw new \RuntimeException("shuffle() failed.");
        }

        return $this;
    }

    /**
     * @param $size
     * @param bool $preserve_keys
     * @return ArrayObject
     */
    function chunk($size, $preserve_keys = false)
    {
        return new ArrayObject(array_chunk($this->array, $size, $preserve_keys));
    }

    /**
     * 交换数组中的键和值
     * @return ArrayObject
     */
    function flip()
    {
        return new ArrayObject(array_flip($this->array));
    }

    /**
     * @param $fn callable
     * @param int $flag
     * @return ArrayObject
     */
    function filter(callable $fn, $flag = 0)
    {
        return new ArrayObject(array_filter($this->array, $fn, $flag));
    }

    /**
     * @param $value
     * @return ArrayObject|StringObject
     */
    static function detectType($value)
    {
        if (is_array($value))
        {
            return new ArrayObject($value);
        }
        elseif (is_string($value))
        {
            return new StringObject($value);
        }
        else
        {
            return $value;
        }
    }

    /**
     * @return array
     */
    function toArray()
    {
        return $this->array;
    }
}
