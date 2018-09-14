/*
  +----------------------------------------------------------------------+
  | PHP-X                                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 The Swoole Group                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the GPL license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.gnu.org/licenses/                                         |
  | If you did not receive a copy of the GPL3.0 license and are unable   |
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "phpx.h"

using namespace std;

namespace php
{

String String::substr(long _offset, long _length)
{

    if ((_length < 0 && (size_t) (-_length) > this->length()))
    {
        return "";
    }
    else if (_length > (zend_long) this->length())
    {
        _length = this->length();
    }

    if (_offset > (zend_long) this->length())
    {
        return "";
    }
    else if (_offset < 0 && -_offset > this->length())
    {
        _offset = 0;
    }

    if (_length < 0 && (_length + (zend_long) this->length() - _offset) < 0)
    {
        return "";
    }

    /* if "from" position is negative, count start position from the end
     * of the string
     */
    if (_offset < 0)
    {
        _offset = (zend_long) this->length() + _offset;
        if (_offset < 0)
        {
            _offset = 0;
        }
    }

    /* if "length" position is negative, set it to the length
     * needed to stop that many chars from the end of the string
     */
    if (_length < 0)
    {
        _length = ((zend_long) this->length() - _offset) + _length;
        if (_length < 0)
        {
            _length = 0;
        }
    }

    if (_offset > (zend_long) this->length())
    {
        return "";
    }

    if ((_offset + _length) > (zend_long) this->length())
    {
        _length = this->length() - _offset;
    }

    return String(value->val + _offset, _length);
}

Variant String::split(String &delim, long limit)
{
	Array retval;
	php_explode(delim.ptr(), value, retval.ptr(), limit);
	return retval;
}

void String::stripTags(String &allow, bool allow_tag_spaces)
{
	value->len = php_strip_tags_ex(this->c_str(), this->length(), nullptr, allow.c_str(), allow.length(), allow_tag_spaces);
}

String String::addSlashes()
{
	return php_addslashes(value, false);
}

String String::basename(String &suffix)
{
	return php_basename(this->c_str(), this->length(), suffix.c_str(), suffix.length());
}

String String::dirname()
{
	size_t n = php_dirname(this->c_str(), this->length());
	return String(this->c_str(), n);
}

void String::stripSlashes()
{
	php_stripslashes(value);
}

}
