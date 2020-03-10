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

#include "static_handler.h"

#include <string>
#include <dirent.h>

using namespace std;
using swoole::http::StaticHandler;

bool StaticHandler::is_modified(const string &date_if_modified_since)
{
    char date_tmp[64];
    if (date_if_modified_since.empty() || date_if_modified_since.length() > sizeof(date_tmp) - 1)
    {
        return false;
    }

    struct tm tm3;
    memcpy(date_tmp, date_if_modified_since.c_str(), date_if_modified_since.length());
    date_tmp[date_if_modified_since.length()] = 0;

    const char *date_format = nullptr;

    if (strptime(date_tmp, SW_HTTP_RFC1123_DATE_GMT, &tm3) != NULL)
    {
        date_format = SW_HTTP_RFC1123_DATE_GMT;
    }
    else if (strptime(date_tmp, SW_HTTP_RFC1123_DATE_UTC, &tm3) != NULL)
    {
        date_format = SW_HTTP_RFC1123_DATE_UTC;
    }
    else if (strptime(date_tmp, SW_HTTP_RFC850_DATE, &tm3) != NULL)
    {
        date_format = SW_HTTP_RFC850_DATE;
    }
    else if (strptime(date_tmp, SW_HTTP_ASCTIME_DATE, &tm3) != NULL)
    {
        date_format = SW_HTTP_ASCTIME_DATE;
    }
    return date_format && mktime(&tm3) - (int) serv->timezone >= get_file_mtime();
}

std::string StaticHandler::get_date()
{
    char date_[64];
    time_t now = time(NULL);
    struct tm *tm1 = gmtime(&now);
    strftime(date_, sizeof(date_), "%a, %d %b %Y %H:%M:%S %Z", tm1);
    return std::string(date_);
}

std::string StaticHandler::get_date_last_modified()
{
    char date_last_modified[64];
    time_t file_mtime = get_file_mtime();
    struct tm *tm2 = gmtime(&file_mtime);
    strftime(date_last_modified, sizeof(date_last_modified), "%a, %d %b %Y %H:%M:%S %Z", tm2);
    return std::string(date_last_modified);
}

bool StaticHandler::hit()
{
    char *p = task.filename;
    const char *url = request_url.c_str();
    size_t url_length = request_url.length();
    /**
     * discard the url parameter
     * [/test.jpg?version=1#position] -> [/test.jpg]
     */
    char *params = (char *) memchr(url, '?', url_length);
    if (params == NULL)
    {
        params = (char *) memchr(url, '#',  url_length);
    }
    size_t n = params ? params - url : url_length;

    memcpy(p, serv->document_root, serv->document_root_len);
    p += serv->document_root_len;

    if (serv->locations->size() > 0)
    {
        for (auto i = serv->locations->begin(); i != serv->locations->end(); i++)
        {
            if (swoole_strcasect(url, url_length, i->c_str(), i->size()))
            {
                last = true;
            }
        }
        if (!last)
        {
            return false;
        }
    }

    if (serv->document_root_len + n >= PATH_MAX)
    {
        return false;
    }

    memcpy(p, url, n);
    p += n;
    *p = '\0';

    l_filename = swHttp_url_decode(task.filename, p - task.filename);
    task.filename[l_filename] = '\0';

    if (swoole_strnpos(url, n, SW_STRL("..")) == -1)
    {
        goto _detect_mime_type;
    }

    char real_path[PATH_MAX];
    if (!realpath(task.filename, real_path))
    {
        if (last)
        {
            status_code = SW_HTTP_NOT_FOUND;
            return true;
        }
        else
        {
            return false;
        }
    }

    if (real_path[serv->document_root_len] != '/')
    {
        return false;
    }

    if (swoole_streq(real_path, strlen(real_path), serv->document_root, serv->document_root_len) != 0)
    {
        return false;
    }

    /**
     * non-static file
     */
    _detect_mime_type:
    /**
     * file does not exist
     */
    if (lstat(task.filename, &file_stat) < 0)
    {
        if (last)
        {
            status_code = SW_HTTP_NOT_FOUND;
            return true;
        }
        else
        {
            return false;
        }
    }

    if(serv->http_autoindex && is_dir())
    {
        return true;
    }

    if (!swoole::mime_type::exists(task.filename))
    {
        return false;
    }

    if ((file_stat.st_mode & S_IFMT) != S_IFREG)
    {
        return false;
    }
    task.length = get_filesize();

    return true;
}

size_t StaticHandler::get_dir_content(char *buffer, size_t size)
{
    int ret = 0;
    char *p = buffer;
    std::string dirname = basename(task.filename);
    struct dirent *ptr;

    DIR *dir = opendir(task.filename);
    if (dir == NULL)
    {
        return -1;
    }

    if (dirname.back() != '/')
    {
        dirname.append("/");
    }

    ret = sw_snprintf(p, size - ret,
        "<html>\n"
        "<head>\n"
        "\t<meta charset='UTF-8'>\n"
        "\t<style>\n"
            "\t\tul{\n"
                "\t\t\tlist-style: none;\n"
                "\t\t\t*list-style: decimal;\n"
                "\t\t\tfont: 15px 'trebuchet MS', 'lucida sans';\n"
                "\t\t\tpadding: 0;\n"
                "\t\t\tmargin-bottom: 4em;\n"
            "\t\t}\n"
        "\t</style>\n"
        "</head>\n"
        "<body>\n"
        "\t<ul>\n"
    );

    p += ret;

    while((ptr = readdir(dir)) != NULL)
    {
        if (strncmp(ptr->d_name, ".", strlen(ptr->d_name)) == 0 ||
                (dirname == "/" && strncmp(ptr->d_name, "..", strlen(ptr->d_name)) == 0))
        {
            continue;
        }
        ret = sw_snprintf(p, size - ret, "\t<li ><a href=%s%s>%s</a></li>\n", dirname.c_str(), ptr->d_name, ptr->d_name);
        p += ret;
    }

    ret = sw_snprintf(p, size - ret,
        "</ul>\n"
        "</body>\n"
        "</html>\n"
    );

    p += ret;

    closedir(dir);
    return p - buffer;
}

int swServer_http_static_handler_add_location(swServer *serv, const char *location, size_t length)
{
    if (serv->locations == nullptr)
    {
        serv->locations = new std::unordered_set<std::string>;
    }
    serv->locations->insert(string(location, length));
    return SW_OK;
}
