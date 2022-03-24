/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include <iostream>
#include <unordered_map>
#include <string>

namespace swoole {
namespace mime_type {
const std::unordered_map<std::string, std::string> &list();
bool add(const std::string &suffix, const std::string &mime_type);
void set(const std::string &suffix, const std::string &mime_type);
bool del(const std::string &suffix);
const std::string &get(const std::string &filename);
bool exists(const std::string &filename);
}  // namespace mime_type
}  // namespace swoole
