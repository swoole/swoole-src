#pragma once

bool swoole_mime_type_add(const char *suffix, const char *mime_type);
void swoole_mime_type_set(const char *suffix, const char *mime_type);
bool swoole_mime_type_delete(const char *suffix, const char *mime_type);
const char* swoole_mime_type_get(const char *file);
bool swoole_mime_type_exists(const char *filename);
