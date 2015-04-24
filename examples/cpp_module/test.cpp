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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include <string>
#include <iostream>

using namespace std;

extern "C"
{
	#include "swoole.h"
	swModule* swModule_init(void);
}

void test(void);

swModule* swModule_init(void)
{
	swModule *module = (swModule *) sw_malloc(sizeof(swModule));
	if (module == NULL)
	{
		swWarn("malloc failed.");
		return NULL;
	}
	string name = "test";
	module->name = (char *)name.c_str();
	module->test = test;
	return module;
}

void test(void)
{
	cout << "hello world" << endl;
}
