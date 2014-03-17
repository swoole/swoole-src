/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */
#ifndef __zc_util_h
#define __zc_util_h

size_t zc_parse_byte_size(char *astring);
int zc_str_replace_env(char *str, size_t str_size);

#define zc_max(a,b) ((a) > (b) ? (a) : (b))
#define zc_min(a,b) ((a) < (b) ? (a) : (b))

#endif
