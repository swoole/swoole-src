/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "swoole.h"

char* swoole_get_mimetype(char *file)
{
    char *dot;
    dot = strrchr(file, '.');
    if (dot == NULL)
    {
        return "text/plain";
    }
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0)
    {
        return "text/html";
    }
    else if (strcasecmp(dot, ".xml") == 0 || strcasecmp(dot, ".htm") == 0)
    {
        return "text/xml";
    }
    else if (strcasecmp(dot, ".css") == 0)
    {
        return "text/css";
    }
    else if (strcasecmp(dot, ".text") == 0)
    {
        return "text/plain";
    }
    else if (strcasecmp(dot, ".jpeg") == 0 || strcasecmp(dot, ".jpg") == 0)
    {
        return "image/jpeg ";
    }
    else if (strcasecmp(dot, ".png") == 0)
    {
        return "image/png";
    }
    else if (strcasecmp(dot, ".gif") == 0)
    {
        return "image/gif";
    }
    else if (strcasecmp(dot, ".json") == 0)
    {
        return "application/json";
    }
    else if (strcasecmp(dot, ".js") == 0)
    {
        return "application/javascript";
    }
    else if (strcasecmp(dot, ".pdf") == 0)
    {
        return "application/pdf";
    }
    else if (strcasecmp(dot, ".doc") == 0)
    {
        return "application/msword";
    }
    else if (strcasecmp(dot, ".xls") == 0)
    {
        return "application/vnd.ms-excel";
    }
    else if (strcasecmp(dot, ".ppt") == 0)
    {
        return "application/vnd.ms-powerpoint";
    }
    else if (strcasecmp(dot, ".docx") == 0)
    {
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    }
    else if (strcasecmp(dot, ".xlsx") == 0)
    {
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    }
    else if (strcasecmp(dot, ".pptx") == 0)
    {
        return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    }
    else if (strcasecmp(dot, ".swf") == 0)
    {
        return "application/x-shockwave-flash";
    }
    else if (strcasecmp(dot, ".zip") == 0)
    {
        return "application/zip";
    }
    else if (strcasecmp(dot, ".mp3") == 0)
    {
        return "audio/mpeg";
    }
    else if (strcasecmp(dot, ".mp4") == 0)
    {
        return "video/mp4";
    }
    else if (strcasecmp(dot, ".mpeg") == 0 || strcasecmp(dot, ".mpg") == 0)
    {
        return "video/mpeg";
    }
    else if (strcasecmp(dot, ".mov") == 0)
    {
        return "video/quicktime";
    }
    else if (strcasecmp(dot, ".flv") == 0)
    {
        return "video/x-flv";
    }
    else if (strcasecmp(dot, ".wmv") == 0)
    {
        return "video/x-ms-wmv";
    }
    else if (strcasecmp(dot, ".avi") == 0)
    {
        return "video/x-msvideo";
    }
    return "application/octet-stream";
}

