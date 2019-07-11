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

#include "server.h"
#include "http.h"
#include "mime_types.h"

#include <string>
#include <unordered_set>

using namespace std;

unordered_set<string> types;
unordered_set<string> locations;

class static_handler
{
private:
    swServer *serv;
    swHttpRequest *request;
    swConnection *conn;
    struct
    {
        off_t offset;
        size_t length;
        char filename[PATH_MAX];
    } task;

    char header_buffer[1024];
    bool last;

    int send_response();
    int send_error_page(int status_code);

public:
    static_handler(swServer *_serv, swHttpRequest *_request, swConnection *_conn)
    {
        serv = _serv;
        request = _request;
        conn = _conn;
        task.length = 0;
        task.offset = 0;
        last = false;
    }
    bool done();
};

int static_handler::send_error_page(int status_code)
{
    swSendData response;
    response.info.fd = conn->session_id;
    response.info.type = SW_EVENT_TCP;
    response.info.len = sw_snprintf(
        header_buffer, sizeof(header_buffer),
        "HTTP/1.1 %s\r\n"
        "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s",
        swHttp_get_status_message(status_code),
        sizeof(SW_HTTP_PAGE_404) - 1, SW_HTTP_PAGE_404
    );
    response.data = header_buffer;
    return swServer_master_send(serv, &response);
}

int static_handler::send_response()
{
    struct stat file_stat;
    /**
     * file does not exist
     */
    if (lstat(task.filename, &file_stat) < 0)
    {
        if (last)
        {
            send_error_page(404);
            return SW_TRUE;
        }
        else
        {
            return SW_FALSE;
        }
    }
    if (file_stat.st_size == 0)
    {
        return SW_FALSE;
    }
    if ((file_stat.st_mode & S_IFMT) != S_IFREG)
    {
        return SW_FALSE;
    }

    swSendData response;
    response.info.fd = conn->session_id;
    response.info.type = SW_EVENT_TCP;

    char *p = request->buffer->str + request->url_offset + request->url_length + 10;
    char *pe = request->buffer->str + request->header_length;

    char *date_if_modified_since = NULL;
    int length_if_modified_since = 0;

    int state = 0;
    for (; p < pe; p++)
    {
        switch (state)
        {
        case 0:
            if (strncasecmp(p, SW_STRL("If-Modified-Since")) == 0)
            {
                p += sizeof("If-Modified-Since");
                state = 1;
            }
            break;
        case 1:
            if (!isspace(*p))
            {
                date_if_modified_since = p;
                state = 2;
            }
            break;
        case 2:
            if (strncasecmp(p, SW_STRL("\r\n")) == 0)
            {
                length_if_modified_since = p - date_if_modified_since;
                goto _check_modify_date;
            }
            break;
        default:
            break;
        }
    }

    char date_[64];
    struct tm *tm1;

    _check_modify_date:
    tm1 = gmtime(&serv->gs->now);
    strftime(date_, sizeof(date_), "%a, %d %b %Y %H:%M:%S %Z", tm1);

    char date_last_modified[64];
#ifdef __MACH__
    time_t file_mtime = file_stat.st_mtimespec.tv_sec;
#else
    time_t file_mtime = file_stat.st_mtim.tv_sec;
#endif

    struct tm *tm2 = gmtime(&file_mtime);
    strftime(date_last_modified, sizeof(date_last_modified), "%a, %d %b %Y %H:%M:%S %Z", tm2);

    if (state == 2)
    {
        struct tm tm3;
        char date_tmp[64];
        memcpy(date_tmp, date_if_modified_since, length_if_modified_since);
        date_tmp[length_if_modified_since] = 0;

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
        if (date_format && mktime(&tm3) - (int) serv->timezone >= file_mtime)
        {
            response.info.len = sw_snprintf(header_buffer, sizeof(header_buffer), "HTTP/1.1 304 Not Modified\r\n"
                    "%s"
                    "Date: %s\r\n"
                    "Last-Modified: %s\r\n"
                    "Server: %s\r\n\r\n", request->keep_alive ? "Connection: keep-alive\r\n" : "", date_,
                    date_last_modified,
                    SW_HTTP_SERVER_SOFTWARE);
            response.data = header_buffer;
            swServer_master_send(serv, &response);
            goto _finish;
        }
    }

    response.info.len = sw_snprintf(header_buffer, sizeof(header_buffer), "HTTP/1.1 200 OK\r\n"
            "%s"
            "Content-Length: %ld\r\n"
            "Content-Type: %s\r\n"
            "Date: %s\r\n"
            "Last-Modified: %s\r\n"
            "Server: %s\r\n\r\n", request->keep_alive ? "Connection: keep-alive\r\n" : "", (long) file_stat.st_size,
            swoole_mime_type_get(task.filename), date_, date_last_modified,
            SW_HTTP_SERVER_SOFTWARE);

    response.data = header_buffer;

#ifdef HAVE_TCP_NOPUSH
    if (conn->tcp_nopush == 0)
    {
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            swSysWarn("swSocket_tcp_nopush() failed");
        }
        conn->tcp_nopush = 1;
    }
#endif
    swServer_master_send(serv, &response);

    task.offset = 0;
    task.length = file_stat.st_size;

    response.info.type = SW_EVENT_SENDFILE;
    response.info.len = sizeof(swSendFile_request) + task.length + 1;
    response.data = (char*) &task;

    swServer_master_send(serv, &response);

    _finish:
    if (!request->keep_alive)
    {
        response.info.type = SW_EVENT_CLOSE;
        response.data = NULL;
        swServer_master_send(serv, &response);
    }

    return SW_TRUE;
}

bool static_handler::done()
{
    char *p = task.filename;
    char *url = request->buffer->str + request->url_offset;

    /**
     * discard the url parameter
     * [/test.jpg?version=1#position] -> [/test.jpg]
     */
    char *params = (char*) memchr(url, '?', request->url_length);
    if (params == NULL)
    {
        params = (char*) memchr(url, '#', request->url_length);
    }
    size_t n = params ? params - url : request->url_length;

    memcpy(p, serv->document_root, serv->document_root_len);
    p += serv->document_root_len;

    if (locations.size() > 0)
    {
        for (auto i = locations.begin(); i != locations.end(); i++)
        {
            if (strncasecmp(i->c_str(), url, i->size()) == 0)
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

    task.filename[swHttp_url_decode(task.filename, p - task.filename)] = '\0';

    if (swoole_strnpos(url, n, SW_STRL("..")) == -1)
    {
        goto _detect_mime_type;
    }

    char real_path[PATH_MAX];
    if (!realpath(task.filename, real_path))
    {
        if (last)
        {
            send_error_page(404);
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

    if (strncmp(real_path, serv->document_root, serv->document_root_len) != 0)
    {
        return false;
    }

    /**
     * non-static file
     */
    _detect_mime_type:
    if (!swoole_mime_type_exists(task.filename))
    {
        return false;
    }

    return send_response();
}

int swHttp_static_handler(swServer *serv, swHttpRequest *request, swConnection *conn)
{
    static_handler handler(serv, request, conn);
    return handler.done();
}

int swHttp_static_handler_add_location(swServer *serv, const char *location, size_t length)
{
    locations.insert(string(location, length));
    return SW_OK;
}
