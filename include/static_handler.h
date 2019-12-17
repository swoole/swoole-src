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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "server.h"
#include "http.h"
#include "mime_types.h"

#include <string>

namespace swoole { namespace http {

class StaticHandler
{
private:
    swServer *serv;
    std::string request_url;
    struct
    {
        off_t offset;
        size_t length;
        char filename[PATH_MAX];
    } task;

    size_t l_filename;
    struct stat file_stat;
    bool last;

public:
    int status_code;
    StaticHandler(swServer *_server, const char *url, size_t url_length) :
            request_url(url, url_length)
    {
        serv = _server;
        task.length = 0;
        task.offset = 0;
        last = false;
        status_code = 200;
        l_filename = 0;
    }
    bool hit();
    bool is_modified(const std::string &date_if_modified_since);

    std::string get_date();

    inline time_t get_file_mtime()
    {
#ifdef __MACH__
        return file_stat.st_mtimespec.tv_sec;
#else
        return file_stat.st_mtim.tv_sec;
#endif
    }

    std::string get_date_last_modified();

    inline const char* get_filename()
    {
        return task.filename;
    }

    inline std::string get_filename_std_string()
    {
        return std::string(task.filename, l_filename);
    }

    inline const size_t get_filesize()
    {
        return file_stat.st_size;
    }

    inline const swSendFile_request* get_task()
    {
        return (const swSendFile_request*) &task;
    }
};

};};
