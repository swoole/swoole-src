<?php

/*
 * This file is part of the swoole/assert package
 * forked from the repository webmozart/assert.
 *
 * (c) Bernhard Schussek <bschussek@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SwooleTest;

use ArrayAccess;
use BadMethodCallException;
use Closure;
use Countable;
use Exception;
use RuntimeException;
use Throwable;
use Traversable;

/**
 * Efficient assertions to validate the input/output of your methods.
 *
 * @method static bool nullOrString($value, $message = '')
 * @method static bool nullOrStringNotEmpty($value, $message = '')
 * @method static bool nullOrInteger($value, $message = '')
 * @method static bool nullOrIntegerish($value, $message = '')
 * @method static bool nullOrFloat($value, $message = '')
 * @method static bool nullOrNumeric($value, $message = '')
 * @method static bool nullOrNatural($value, $message = '')
 * @method static bool nullOrBoolean($value, $message = '')
 * @method static bool nullOrScalar($value, $message = '')
 * @method static bool nullOrObject($value, $message = '')
 * @method static bool nullOrResource($value, $type = null, $message = '')
 * @method static bool nullOrIsCallable($value, $message = '')
 * @method static bool nullOrIsArray($value, $message = '')
 * @method static bool nullOrIsTraversable($value, $message = '')
 * @method static bool nullOrIsArrayAccessible($value, $message = '')
 * @method static bool nullOrIsCountable($value, $message = '')
 * @method static bool nullOrIsIterable($value, $message = '')
 * @method static bool nullOrIsInstanceOf($value, $class, $message = '')
 * @method static bool nullOrNotInstanceOf($value, $class, $message = '')
 * @method static bool nullOrIsInstanceOfAny($value, $classes, $message = '')
 * @method static bool nullOrIsEmpty($value, $message = '')
 * @method static bool nullOrNotEmpty($value, $message = '')
 * @method static bool nullOrTrue($value, $message = '')
 * @method static bool nullOrFalse($value, $message = '')
 * @method static bool nullOrIp($value, $message = '')
 * @method static bool nullOrIpv4($value, $message = '')
 * @method static bool nullOrIpv6($value, $message = '')
 * @method static bool nullOrUniqueValues($values, $message = '')
 * @method static bool nullOrEq($value, $expect, $message = '')
 * @method static bool nullOrNotEq($value, $expect, $message = '')
 * @method static bool nullOrSame($value, $expect, $message = '')
 * @method static bool nullOrNotSame($value, $expect, $message = '')
 * @method static bool nullOrGreaterThan($value, $limit, $message = '')
 * @method static bool nullOrGreaterThanEq($value, $limit, $message = '')
 * @method static bool nullOrLessThan($value, $limit, $message = '')
 * @method static bool nullOrLessThanEq($value, $limit, $message = '')
 * @method static bool nullOrRange($value, $min, $max, $message = '')
 * @method static bool nullOrOneOf($value, $values, $message = '')
 * @method static bool nullOrContains($value, $subString, $message = '')
 * @method static bool nullOrNotContains($value, $subString, $message = '')
 * @method static bool nullOrNotWhitespaceOnly($value, $message = '')
 * @method static bool nullOrStartsWith($value, $prefix, $message = '')
 * @method static bool nullOrStartsWithLetter($value, $message = '')
 * @method static bool nullOrEndsWith($value, $suffix, $message = '')
 * @method static bool nullOrRegex($value, $pattern, $message = '')
 * @method static bool nullOrNotRegex($value, $pattern, $message = '')
 * @method static bool nullOrAlpha($value, $message = '')
 * @method static bool nullOrDigits($value, $message = '')
 * @method static bool nullOrAlnum($value, $message = '')
 * @method static bool nullOrLower($value, $message = '')
 * @method static bool nullOrUpper($value, $message = '')
 * @method static bool nullOrLength($value, $length, $message = '')
 * @method static bool nullOrMinLength($value, $min, $message = '')
 * @method static bool nullOrMaxLength($value, $max, $message = '')
 * @method static bool nullOrLengthBetween($value, $min, $max, $message = '')
 * @method static bool nullOrFileExists($value, $message = '')
 * @method static bool nullOrFile($value, $message = '')
 * @method static bool nullOrDirectory($value, $message = '')
 * @method static bool nullOrReadable($value, $message = '')
 * @method static bool nullOrWritable($value, $message = '')
 * @method static bool nullOrClassExists($value, $message = '')
 * @method static bool nullOrSubclassOf($value, $class, $message = '')
 * @method static bool nullOrInterfaceExists($value, $message = '')
 * @method static bool nullOrImplementsInterface($value, $interface, $message = '')
 * @method static bool nullOrPropertyExists($value, $property, $message = '')
 * @method static bool nullOrPropertyNotExists($value, $property, $message = '')
 * @method static bool nullOrMethodExists($value, $method, $message = '')
 * @method static bool nullOrMethodNotExists($value, $method, $message = '')
 * @method static bool nullOrKeyExists($value, $key, $message = '')
 * @method static bool nullOrKeyNotExists($value, $key, $message = '')
 * @method static bool nullOrCount($value, $key, $message = '')
 * @method static bool nullOrMinCount($value, $min, $message = '')
 * @method static bool nullOrMaxCount($value, $max, $message = '')
 * @method static bool nullOrIsList($value, $message = '')
 * @method static bool nullOrIsMap($value, $message = '')
 * @method static bool nullOrCountBetween($value, $min, $max, $message = '')
 * @method static bool nullOrUuid($values, $message = '')
 * @method static bool nullOrThrows($expression, $class = 'Exception', $message = '')
 * @method static bool allString($values, $message = '')
 * @method static bool allStringNotEmpty($values, $message = '')
 * @method static bool allInteger($values, $message = '')
 * @method static bool allIntegerish($values, $message = '')
 * @method static bool allFloat($values, $message = '')
 * @method static bool allNumeric($values, $message = '')
 * @method static bool allNatural($values, $message = '')
 * @method static bool allBoolean($values, $message = '')
 * @method static bool allScalar($values, $message = '')
 * @method static bool allObject($values, $message = '')
 * @method static bool allResource($values, $type = null, $message = '')
 * @method static bool allIsCallable($values, $message = '')
 * @method static bool allIsArray($values, $message = '')
 * @method static bool allIsTraversable($values, $message = '')
 * @method static bool allIsArrayAccessible($values, $message = '')
 * @method static bool allIsCountable($values, $message = '')
 * @method static bool allIsIterable($values, $message = '')
 * @method static bool allIsInstanceOf($values, $class, $message = '')
 * @method static bool allNotInstanceOf($values, $class, $message = '')
 * @method static bool allIsInstanceOfAny($values, $classes, $message = '')
 * @method static bool allNull($values, $message = '')
 * @method static bool allNotNull($values, $message = '')
 * @method static bool allIsEmpty($values, $message = '')
 * @method static bool allNotEmpty($values, $message = '')
 * @method static bool allTrue($values, $message = '')
 * @method static bool allFalse($values, $message = '')
 * @method static bool allIp($values, $message = '')
 * @method static bool allIpv4($values, $message = '')
 * @method static bool allIpv6($values, $message = '')
 * @method static bool allUniqueValues($values, $message = '')
 * @method static bool allEq($values, $expect, $message = '')
 * @method static bool allNotEq($values, $expect, $message = '')
 * @method static bool allSame($values, $expect, $message = '')
 * @method static bool allNotSame($values, $expect, $message = '')
 * @method static bool allGreaterThan($values, $limit, $message = '')
 * @method static bool allGreaterThanEq($values, $limit, $message = '')
 * @method static bool allLessThan($values, $limit, $message = '')
 * @method static bool allLessThanEq($values, $limit, $message = '')
 * @method static bool allRange($values, $min, $max, $message = '')
 * @method static bool allOneOf($values, $values, $message = '')
 * @method static bool allContains($values, $subString, $message = '')
 * @method static bool allNotContains($values, $subString, $message = '')
 * @method static bool allNotWhitespaceOnly($values, $message = '')
 * @method static bool allStartsWith($values, $prefix, $message = '')
 * @method static bool allStartsWithLetter($values, $message = '')
 * @method static bool allEndsWith($values, $suffix, $message = '')
 * @method static bool allRegex($values, $pattern, $message = '')
 * @method static bool allNotRegex($values, $pattern, $message = '')
 * @method static bool allAlpha($values, $message = '')
 * @method static bool allDigits($values, $message = '')
 * @method static bool allAlnum($values, $message = '')
 * @method static bool allLower($values, $message = '')
 * @method static bool allUpper($values, $message = '')
 * @method static bool allLength($values, $length, $message = '')
 * @method static bool allMinLength($values, $min, $message = '')
 * @method static bool allMaxLength($values, $max, $message = '')
 * @method static bool allLengthBetween($values, $min, $max, $message = '')
 * @method static bool allFileExists($values, $message = '')
 * @method static bool allFile($values, $message = '')
 * @method static bool allDirectory($values, $message = '')
 * @method static bool allReadable($values, $message = '')
 * @method static bool allWritable($values, $message = '')
 * @method static bool allClassExists($values, $message = '')
 * @method static bool allSubclassOf($values, $class, $message = '')
 * @method static bool allInterfaceExists($values, $message = '')
 * @method static bool allImplementsInterface($values, $interface, $message = '')
 * @method static bool allPropertyExists($values, $property, $message = '')
 * @method static bool allPropertyNotExists($values, $property, $message = '')
 * @method static bool allMethodExists($values, $method, $message = '')
 * @method static bool allMethodNotExists($values, $method, $message = '')
 * @method static bool allKeyExists($values, $key, $message = '')
 * @method static bool allKeyNotExists($values, $key, $message = '')
 * @method static bool allCount($values, $key, $message = '')
 * @method static bool allMinCount($values, $min, $message = '')
 * @method static bool allMaxCount($values, $max, $message = '')
 * @method static bool allCountBetween($values, $min, $max, $message = '')
 * @method static bool allIsList($values, $message = '')
 * @method static bool allIsMap($values, $message = '')
 * @method static bool allUuid($values, $message = '')
 * @method static bool allThrows($expressions, $class = 'Exception', $message = '')
 *
 * @since  2.0
 *
 * @author Bernhard Schussek <bschussek@gmail.com>
 */
class Assert
{
    protected static $throwException = true;
    protected static $maxStringLength = 1024;

    public static function setThrowException(bool $b)
    {
        static::$throwException = $b;
    }

    public static function assert($value, $message = ''): bool
    {
        if (!$value) {
            static::reportInvalidArgument($message);
            return false;
        }
        return true;
    }

    public static function string($value, $message = ''): bool
    {
        if (!is_string($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a string. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function stringNotEmpty($value, $message = ''): bool
    {
        return static::string($value, $message) && static::notEq($value, '', $message);
    }

    public static function integer($value, $message = ''): bool
    {
        if (!is_int($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an integer. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function integerish($value, $message = ''): bool
    {
        if (!is_numeric($value) || $value != (int)$value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an integerish value. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function float($value, $message = ''): bool
    {
        if (!is_float($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a float. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function numeric($value, $message = ''): bool
    {
        if (!is_numeric($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a numeric. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function natural($value, $message = ''): bool
    {
        if (!is_int($value) || $value < 0) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a non-negative integer. Got %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function boolean($value, $message = ''): bool
    {
        if (!is_bool($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a boolean. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function scalar($value, $message = ''): bool
    {
        if (!is_scalar($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a scalar. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function object($value, $message = ''): bool
    {
        if (!is_object($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an object. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function resource($value, $type = null, $message = ''): bool
    {
        if (!is_resource($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a resource. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        if ($type && $type !== get_resource_type($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a resource of type %2$s. Got: %s',
                static::typeToString($value),
                $type
            ));
            return false;
        }
        return true;
    }

    public static function isCallable($value, $message = ''): bool
    {
        if (!is_callable($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a callable. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function isArray($value, $message = ''): bool
    {
        if (!is_array($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function isArrayAccessible($value, $message = ''): bool
    {
        if (!is_array($value) && !($value instanceof ArrayAccess)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array accessible. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function isCountable($value, $message = ''): bool
    {
        if (!is_array($value) && !($value instanceof Countable)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a countable. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function isIterable($value, $message = ''): bool
    {
        if (!is_array($value) && !($value instanceof Traversable)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an iterable. Got: %s',
                static::typeToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function isInstanceOf($value, $class, $message = ''): bool
    {
        if (!($value instanceof $class)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an instance of %2$s. Got: %s',
                static::typeToString($value),
                $class
            ));
            return false;
        }
        return true;
    }

    public static function notInstanceOf($value, $class, $message = ''): bool
    {
        if ($value instanceof $class) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an instance other than %2$s. Got: %s',
                static::typeToString($value),
                $class
            ));
            return false;
        }
        return true;
    }

    public static function isInstanceOfAny($value, array $classes, $message = ''): bool
    {
        foreach ($classes as $class) {
            if ($value instanceof $class) {
                return true;
            }
        }
        static::reportInvalidArgument(sprintf(
            $message ?: 'Expected an instance of any of %2$s. Got: %s',
            static::typeToString($value),
            implode(', ', array_map(['static', 'valueToString'], $classes))
        ));
        return false;
    }

    public static function isEmpty($value, $message = ''): bool
    {
        if (!empty($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an empty value. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function notEmpty($value, $message = ''): bool
    {
        if (empty($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a non-empty value. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function null($value, $message = ''): bool
    {
        if (null !== $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected null. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function notNull($value, $message = ''): bool
    {
        if (null === $value) {
            static::reportInvalidArgument(
                $message ?: 'Expected a value other than null.'
            );
            return false;
        }
        return true;
    }

    public static function true($value, $message = ''): bool
    {
        if (true !== $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to be true. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function false($value, $message = ''): bool
    {
        if (false !== $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to be false. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function ip($value, $message = ''): bool
    {
        if (false === filter_var($value, FILTER_VALIDATE_IP)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to be an IP. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function ipv4($value, $message = ''): bool
    {
        if (false === filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to be an IPv4. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function ipv6($value, $message = ''): bool
    {
        if (false === filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to be an IPv6. Got %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function uniqueValues(array $values, $message = ''): bool
    {
        $allValues = count($values);
        $uniqueValues = count(array_unique($values));
        if ($allValues !== $uniqueValues) {
            $difference = $allValues - $uniqueValues;
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array of unique values, but %s of them %s duplicated',
                $difference,
                (1 === $difference ? 'is' : 'are')
            ));
            return false;
        }
        return true;
    }

    public static function eq($value, $expect, $message = ''): bool
    {
        if ($expect != $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value equal to %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($expect)
            ));
            return false;
        }
        return true;
    }

    public static function notEq($value, $expect, $message = ''): bool
    {
        if ($expect == $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a different value than %s.',
                static::valueToString($expect)
            ));
            return false;
        }
        return true;
    }

    public static function same($value, $expect, $message = ''): bool
    {
        if ($expect !== $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value identical to %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($expect)
            ));
            return false;
        }
        return true;
    }

    public static function notSame($value, $expect, $message = ''): bool
    {
        if ($expect === $value) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value not identical to %s.',
                static::valueToString($expect)
            ));
            return false;
        }
        return true;
    }

    public static function greaterThan($value, $limit, $message = ''): bool
    {
        if ($value <= $limit) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value greater than %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($limit)
            ));
            return false;
        }
        return true;
    }

    public static function greaterThanEq($value, $limit, $message = ''): bool
    {
        if ($value < $limit) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value greater than or equal to %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($limit)
            ));
            return false;
        }
        return true;
    }

    public static function lessThan($value, $limit, $message = ''): bool
    {
        if ($value >= $limit) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value less than %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($limit)
            ));
            return false;
        }
        return true;
    }

    public static function lessThanEq($value, $limit, $message = ''): bool
    {
        if ($value > $limit) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value less than or equal to %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($limit)
            ));
            return false;
        }
        return true;
    }

    public static function range($value, $min, $max, $message = ''): bool
    {
        if ($value < $min || $value > $max) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value between %2$s and %3$s. Got: %s',
                static::valueToString($value),
                static::valueToString($min),
                static::valueToString($max)
            ));
            return false;
        }
        return true;
    }

    public static function approximate($value, $actual, float $ratio = 0.1): bool
    {
        $ret = $actual * (1 - $ratio) < $value && $actual * (1 + $ratio) > $value;
        if (!$ret) {
            static::reportInvalidArgument(
                "Expected a value approximate {$value}, but got {$actual}\n"
            );
        }
        return $ret;
    }

    public static function oneOf($value, array $values, $message = ''): bool
    {
        if (!in_array($value, $values, true)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected one of: %2$s. Got: %s',
                static::valueToString($value),
                implode(', ', array_map(['static', 'valueToString'], $values))
            ));
            return false;
        }
        return true;
    }

    public static function contains($value, $subString, $message = ''): bool
    {
        if (false === strpos($value, $subString)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($subString)
            ));
            return false;
        }
        return true;
    }

    public static function notContains($value, $subString, $message = ''): bool
    {
        if (false !== strpos($value, $subString)) {
            static::reportInvalidArgument(sprintf(
                $message ?: '%2$s was not expected to be contained in a value. Got: %s',
                static::valueToString($value),
                static::valueToString($subString)
            ));
            return false;
        }
        return true;
    }

    public static function notWhitespaceOnly($value, $message = ''): bool
    {
        if (preg_match('/^\s*$/', $value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a non-whitespace string. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function startsWith($value, $prefix, $message = ''): bool
    {
        if (0 !== strpos($value, $prefix)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to start with %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($prefix)
            ));
            return false;
        }
        return true;
    }

    public static function startsWithLetter($value, $message = ''): bool
    {
        $valid = isset($value[0]);

        if ($valid) {
            $locale = setlocale(LC_CTYPE, 0);
            setlocale(LC_CTYPE, 'C');
            $valid = ctype_alpha($value[0]);
            setlocale(LC_CTYPE, $locale);
        }

        if (!$valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to start with a letter. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function endsWith($value, $suffix, $message = ''): bool
    {
        if ($suffix !== substr($value, -static::strlen($suffix))) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to end with %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($suffix)
            ));
            return false;
        }
        return true;
    }

    public static function regex($value, $pattern, $message = ''): bool
    {
        if (!preg_match($pattern, $value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The value %s does not match the expected pattern.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function notRegex($value, $pattern, $message = ''): bool
    {
        if (preg_match($pattern, $value, $matches, PREG_OFFSET_CAPTURE)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The value %s matches the pattern %s (at offset %d).',
                static::valueToString($value),
                static::valueToString($pattern),
                $matches[0][1]
            ));
            return false;
        }
        return true;
    }

    public static function alpha($value, $message = ''): bool
    {
        $locale = setlocale(LC_CTYPE, 0);
        setlocale(LC_CTYPE, 'C');
        $valid = !ctype_alpha($value);
        setlocale(LC_CTYPE, $locale);

        if ($valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain only letters. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function digits($value, $message = ''): bool
    {
        $locale = setlocale(LC_CTYPE, 0);
        setlocale(LC_CTYPE, 'C');
        $valid = !ctype_digit($value);
        setlocale(LC_CTYPE, $locale);

        if ($valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain digits only. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function alnum($value, $message = ''): bool
    {
        $locale = setlocale(LC_CTYPE, 0);
        setlocale(LC_CTYPE, 'C');
        $valid = !ctype_alnum($value);
        setlocale(LC_CTYPE, $locale);

        if ($valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain letters and digits only. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function lower($value, $message = ''): bool
    {
        $locale = setlocale(LC_CTYPE, 0);
        setlocale(LC_CTYPE, 'C');
        $valid = !ctype_lower($value);
        setlocale(LC_CTYPE, $locale);

        if ($valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain lowercase characters only. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function upper($value, $message = ''): bool
    {
        $locale = setlocale(LC_CTYPE, 0);
        setlocale(LC_CTYPE, 'C');
        $valid = !ctype_upper($value);
        setlocale(LC_CTYPE, $locale);

        if ($valid) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain uppercase characters only. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function length($value, $length, $message = ''): bool
    {
        if ($length !== static::strlen($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain %2$s characters. Got: %s',
                static::valueToString($value),
                $length
            ));
            return false;
        }
        return true;
    }

    public static function minLength($value, $min, $message = ''): bool
    {
        if (static::strlen($value) < $min) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain at least %2$s characters. Got: %s',
                static::valueToString($value),
                $min
            ));
            return false;
        }
        return true;
    }

    public static function maxLength($value, $max, $message = ''): bool
    {
        if (static::strlen($value) > $max) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain at most %2$s characters. Got: %s',
                static::valueToString($value),
                $max
            ));
            return false;
        }
        return true;
    }

    public static function lengthBetween($value, $min, $max, $message = ''): bool
    {
        $length = static::strlen($value);

        if ($length < $min || $length > $max) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a value to contain between %2$s and %3$s characters. Got: %s',
                static::valueToString($value),
                $min,
                $max
            ));
            return false;
        }
        return true;
    }

    public static function fileExists($value, $message = ''): bool
    {
        static::string($value);

        if (!file_exists($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The file %s does not exist.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function file($value, $message = ''): bool
    {
        static::fileExists($value, $message);

        if (!is_file($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The path %s is not a file.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function directory($value, $message = ''): bool
    {
        static::fileExists($value, $message);

        if (!is_dir($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The path %s is no directory.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function readable($value, $message = ''): bool
    {
        if (!is_readable($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The path %s is not readable.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function writable($value, $message = ''): bool
    {
        if (!is_writable($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'The path %s is not writable.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function classExists($value, $message = ''): bool
    {
        if (!class_exists($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an existing class name. Got: %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function subclassOf($value, $class, $message = ''): bool
    {
        if (!is_subclass_of($value, $class)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected a sub-class of %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($class)
            ));
            return false;
        }
        return true;
    }

    public static function interfaceExists($value, $message = ''): bool
    {
        if (!interface_exists($value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an existing interface name. got %s',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function implementsInterface($value, $interface, $message = ''): bool
    {
        if (!in_array($interface, class_implements($value))) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an implementation of %2$s. Got: %s',
                static::valueToString($value),
                static::valueToString($interface)
            ));
            return false;
        }
        return true;
    }

    public static function propertyExists($classOrObject, $property, $message = ''): bool
    {
        if (!property_exists($classOrObject, $property)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the property %s to exist.',
                static::valueToString($property)
            ));
            return false;
        }
        return true;
    }

    public static function propertyNotExists($classOrObject, $property, $message = ''): bool
    {
        if (property_exists($classOrObject, $property)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the property %s to not exist.',
                static::valueToString($property)
            ));
            return false;
        }
        return true;
    }

    public static function methodExists($classOrObject, $method, $message = ''): bool
    {
        if (!method_exists($classOrObject, $method)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the method %s to exist.',
                static::valueToString($method)
            ));
            return false;
        }
        return true;
    }

    public static function methodNotExists($classOrObject, $method, $message = ''): bool
    {
        if (method_exists($classOrObject, $method)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the method %s to not exist.',
                static::valueToString($method)
            ));
            return false;
        }
        return true;
    }

    public static function keyExists($array, $key, $message = ''): bool
    {
        if (!(isset($array[$key]) || array_key_exists($key, $array))) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the key %s to exist.',
                static::valueToString($key)
            ));
            return false;
        }
        return true;
    }

    public static function keyNotExists($array, $key, $message = ''): bool
    {
        if (isset($array[$key]) || array_key_exists($key, $array)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected the key %s to not exist.',
                static::valueToString($key)
            ));
            return false;
        }
        return true;
    }

    public static function count($array, $number, $message = ''): bool
    {
        return static::eq(
            count($array),
            $number,
            $message ?: sprintf('Expected an array to contain %d elements. Got: %d.', $number, count($array))
        );
    }

    public static function minCount($array, $min, $message = ''): bool
    {
        if (count($array) < $min) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array to contain at least %2$d elements. Got: %d',
                count($array),
                $min
            ));
            return false;
        }
        return true;
    }

    public static function maxCount($array, $max, $message = ''): bool
    {
        if (count($array) > $max) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array to contain at most %2$d elements. Got: %d',
                count($array),
                $max
            ));
            return false;
        }
        return true;
    }

    public static function countBetween($array, $min, $max, $message = ''): bool
    {
        $count = count($array);

        if ($count < $min || $count > $max) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Expected an array to contain between %2$d and %3$d elements. Got: %d',
                $count,
                $min,
                $max
            ));
            return false;
        }
        return true;
    }

    public static function isList($array, $message = ''): bool
    {
        if (!is_array($array) || !$array || array_keys($array) !== range(0, count($array) - 1)) {
            static::reportInvalidArgument(
                $message ?: 'Expected list - non-associative array.'
            );
            return false;
        }
        return true;
    }

    public static function isMap($array, $message = ''): bool
    {
        if (
            !is_array($array) ||
            !$array ||
            array_keys($array) !== array_filter(array_keys($array), function ($key) {
                return is_string($key);
            })
        ) {
            static::reportInvalidArgument(
                $message ?: 'Expected map - associative array with string keys.'
            );
            return false;
        }
        return true;
    }

    public static function uuid($value, $message = ''): bool
    {
        $value = str_replace(['urn:', 'uuid:', '{', '}'], '', $value);

        // The nil UUID is special form of UUID that is specified to have all
        // 128 bits set to zero.
        if ('00000000-0000-0000-0000-000000000000' === $value) {
            return true;
        }

        if (!preg_match('/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/', $value)) {
            static::reportInvalidArgument(sprintf(
                $message ?: 'Value %s is not a valid UUID.',
                static::valueToString($value)
            ));
            return false;
        }
        return true;
    }

    public static function throws(Closure $expression, $class = 'Exception', $message = ''): bool
    {
        static::string($class);

        $actual = 'none';

        try {
            $expression();
        } catch (Exception $e) {
            $actual = get_class($e);
            if ($e instanceof $class) {
                return true;
            }
        } catch (Throwable $e) {
            $actual = get_class($e);
            if ($e instanceof $class) {
                return true;
            }
        }

        static::reportInvalidArgument($message ?: sprintf(
            'Expected to throw "%s", got "%s"',
            $class,
            $actual
        ));
        return false;
    }

    public static function __callStatic($name, $arguments): bool
    {
        if ('nullOr' === substr($name, 0, 6)) {
            if (null !== $arguments[0]) {
                $method = lcfirst(substr($name, 6));
                if (!call_user_func_array(['static', $method], $arguments)) {
                    return false;
                }
            }

            return true;
        }

        if ('all' === substr($name, 0, 3)) {
            if (!static::isIterable($arguments[0])) {
                return false;
            }

            $method = lcfirst(substr($name, 3));
            $args = $arguments;

            foreach ($arguments[0] as $entry) {
                $args[0] = $entry;
                if (!call_user_func_array(['static', $method], $args)) {
                    return false;
                }
            }

            return true;
        }

        throw new BadMethodCallException('No such method: ' . $name);
    }

    protected static function valueToString($value): string
    {
        if (null === $value) {
            return 'null';
        }

        if (true === $value) {
            return 'true';
        }

        if (false === $value) {
            return 'false';
        }

        if (is_array($value)) {
            return 'array(' . count($value) . ')';
        }

        if (is_object($value)) {
            if (method_exists($value, '__toString')) {
                return get_class($value) . ': ' . self::valueToString($value->__toString());
            }
            return get_class($value);
        }

        if (is_resource($value)) {
            return 'resource';
        }

        if (is_string($value)) {
            $length = strlen($value);
            if ($length > static::$maxStringLength) {
                $value = substr($value, 0, static::$maxStringLength) . '...';
            }
            return 'string(' . $length . ') "' . $value . '"';
        }

        return (string)$value;
    }

    protected static function typeToString($value): string
    {
        return is_object($value) ? get_class($value) : gettype($value);
    }

    protected static function strlen($value): int
    {
        if (!function_exists('mb_detect_encoding')) {
            return strlen($value);
        }

        if (false === $encoding = mb_detect_encoding($value)) {
            return strlen($value);
        }

        return mb_strwidth($value, $encoding);
    }

    protected static function reportInvalidArgument(string $message = '')
    {
        $e = new RuntimeException($message);
        if (static::$throwException) {
            throw $e;
        } else {
            $file = $e->getFile();
            $line = $e->getLine();
            $msg = $e->getMessage();
            $trace = $e->getTraceAsString();
            foreach ($e->getTrace() as $call) {
                $file = $call['file'] ?? 'Unknown';
                $line = $call['line'] ?? 0;
                if ($file !== __FILE__) {
                    break;
                }
            }
            echo "\nAssert failed: " . (empty($msg) ? '' : "{$msg} ") . "in {$file} on line {$line}\nStack trace: \n{$trace}\n";
        }
    }

    private function __construct()
    {
    }
}
