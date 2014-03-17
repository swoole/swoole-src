# zlog makefile
# Copyright (C) 2010-2012 Hardy Simpson <HardySimpson1984@gmail.com>
# This file is released under the LGPL 2.1 license, see the COPYING file

OBJ=    \
  buf.o    \
  category.o    \
  category_table.o    \
  conf.o    \
  event.o    \
  format.o    \
  level.o    \
  level_list.o    \
  mdc.o    \
  record.o    \
  record_table.o    \
  rotater.o    \
  rule.o    \
  spec.o    \
  thread.o    \
  zc_arraylist.o    \
  zc_hashtable.o    \
  zc_profile.o    \
  zc_util.o    \
  zlog.o
BINS=zlog-chk-conf
LIBNAME=libzlog

ZLOG_MAJOR=1
ZLOG_MINOR=2

# Fallback to gcc when $CC is not in $PATH.
CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')
OPTIMIZATION?=-O2
WARNINGS=-Wall -Werror -Wstrict-prototypes -fwrapv
DEBUG?= -g -ggdb
REAL_CFLAGS=$(OPTIMIZATION) -fPIC -pthread $(CFLAGS) $(WARNINGS) $(DEBUG)
REAL_LDFLAGS=$(LDFLAGS) -pthread

DYLIBSUFFIX=so
STLIBSUFFIX=a
DYLIB_MINOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(ZLOG_MAJOR).$(ZLOG_MINOR)
DYLIB_MAJOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(ZLOG_MAJOR)
DYLIBNAME=$(LIBNAME).$(DYLIBSUFFIX)
DYLIB_MAKE_CMD=$(CC) -shared -Wl,-soname,$(DYLIB_MINOR_NAME) -o $(DYLIBNAME) $(LDFLAGS)
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)
STLIB_MAKE_CMD=ar rcs $(STLIBNAME)

# Installation related variables
PREFIX?=/usr/local
INCLUDE_PATH?=include
LIBRARY_PATH?=lib
INSTALL_INCLUDE_PATH= $(PREFIX)/$(INCLUDE_PATH)
INSTALL_LIBRARY_PATH= $(PREFIX)/$(LIBRARY_PATH)

# Platform-specific overrides
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(uname_S),SunOS)
#  REAL_LDFLAGS+= -ldl -lnsl -lsocket
  DYLIB_MAKE_CMD=$(CC) -G -o $(DYLIBNAME) -h $(DYLIB_MINOR_NAME) $(LDFLAGS)
  INSTALL= cp -r
endif
ifeq ($(uname_S),Darwin)
  DYLIBSUFFIX=dylib
  DYLIB_MINOR_NAME=$(LIBNAME).$(ZLOG_MAJOR).$(ZLOG_MINOR).$(DYLIBSUFFIX)
  DYLIB_MAJOR_NAME=$(LIBNAME).$(ZLOG_MAJOR).$(DYLIBSUFFIX)
  DYLIB_MAKE_CMD=$(CC) -dynamiclib -install_name $(INSTALL_LIBRARY_PATH)/$(DYLIB_MINOR_NAME) -o $(DYLIBNAME) $(LDFLAGS)
endif

ifeq ($(uname_S),AIX)
  # this logic of minor major is not relevant on AIX or at least not widely used
  # not to mention dynamic linker .a preference...
  DYLIB_MAKE_CMD=$(CC) -shared -Wl,-G,-b64 -maix64 -pthread -o $(DYLIBNAME) $(LDFLAGS)
  REAL_CFLAGS+= -maix64
  STLIB_MAKE_CMD=OBJECT_MODE=64 ar rcs $(STLIBNAME) $(DYLIB_MAJOR_NAME)
endif

all: $(DYLIBNAME) $(BINS)

# Deps (use make dep to generate this)
buf.o: buf.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h buf.h
category.o: category.c fmacros.h category.h zc_defs.h zc_profile.h \
 zc_arraylist.h zc_hashtable.h zc_xplatform.h zc_util.h thread.h event.h \
 buf.h mdc.h rule.h format.h rotater.h record.h
category_table.o: category_table.c zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h category_table.h category.h \
 thread.h event.h buf.h mdc.h
conf.o: conf.c fmacros.h conf.h zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h format.h thread.h event.h buf.h \
 mdc.h rotater.h rule.h record.h level_list.h level.h
event.o: event.c fmacros.h zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h event.h
format.o: format.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h thread.h event.h buf.h mdc.h spec.h format.h
level.o: level.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h level.h
level_list.o: level_list.c zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h level.h level_list.h
mdc.o: mdc.c mdc.h zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h
record.o: record.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h record.h
record_table.o: record_table.c zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h record_table.h record.h
rotater.o: rotater.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h rotater.h
rule.o: rule.c fmacros.h rule.h zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h format.h thread.h event.h buf.h \
 mdc.h rotater.h record.h level_list.h level.h spec.h
spec.o: spec.c fmacros.h spec.h event.h zc_defs.h zc_profile.h \
 zc_arraylist.h zc_hashtable.h zc_xplatform.h zc_util.h buf.h thread.h \
 mdc.h level_list.h level.h
thread.o: thread.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h event.h buf.h thread.h mdc.h
zc_arraylist.o: zc_arraylist.c zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h
zc_hashtable.o: zc_hashtable.c zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h
zc_profile.o: zc_profile.c fmacros.h zc_profile.h zc_xplatform.h
zc_util.o: zc_util.c zc_defs.h zc_profile.h zc_arraylist.h zc_hashtable.h \
 zc_xplatform.h zc_util.h
zlog-chk-conf.o: zlog-chk-conf.c fmacros.h zlog.h
zlog.o: zlog.c fmacros.h conf.h zc_defs.h zc_profile.h zc_arraylist.h \
 zc_hashtable.h zc_xplatform.h zc_util.h format.h thread.h event.h buf.h \
 mdc.h rotater.h category_table.h category.h record_table.h \
 record.h rule.h

$(DYLIBNAME): $(OBJ)
	$(DYLIB_MAKE_CMD) $(OBJ) $(REAL_LDFLAGS)
	# for use in test folder - linux and requirement for aix runtime
	# resolving
	cp -f $(DYLIBNAME) $(DYLIB_MAJOR_NAME)
	cp -f $(DYLIBNAME) $(DYLIB_MINOR_NAME)

$(STLIBNAME): $(OBJ)
	$(STLIB_MAKE_CMD) $(OBJ)

dynamic: $(DYLIBNAME)
static: $(STLIBNAME)

# Binaries:
zlog-chk-conf: zlog-chk-conf.o $(STLIBNAME) $(DYLIBNAME)
	$(CC) -o $@ zlog-chk-conf.o -L. -lzlog $(REAL_LDFLAGS)

.c.o:
	$(CC) -std=c99 -pedantic -c $(REAL_CFLAGS) $<

clean:
	rm -rf $(DYLIBNAME) $(STLIBNAME) $(BINS) *.o *.gcda *.gcno *.gcov $(DYLIB_MINOR_NAME)

dep:
	$(CC) -MM *.c

# Installation target

ifeq ($(uname_S),SunOS)
  INSTALL?= cp -r
endif

ifeq ($(uname_S),AIX)
  INSTALL?= cp -r
endif


INSTALL?= cp -a

install: $(DYLIBNAME) $(STLIBNAME)
	mkdir -p $(INSTALL_INCLUDE_PATH) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) zlog.h $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(DYLIBNAME) $(INSTALL_LIBRARY_PATH)/$(DYLIB_MINOR_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MINOR_NAME) $(DYLIB_MAJOR_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MAJOR_NAME) $(DYLIBNAME)
	$(INSTALL) $(STLIBNAME) $(INSTALL_LIBRARY_PATH)

32bit:
	@echo ""
	@echo "WARNING: if this fails under Linux you probably need to install libc6-dev-i386"
	@echo ""
	$(MAKE) CFLAGS="-m32" LDFLAGS="-m32"

gprof:
	$(MAKE) CFLAGS="-pg" LDFLAGS="-pg"

gcov:
	$(MAKE) CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs"

coverage: gcov
	make check
	mkdir -p tmp/lcov
	lcov -d . -c -o tmp/lcov/hiredis.info
	genhtml --legend -o tmp/lcov/report tmp/lcov/hiredis.info

noopt:
	$(MAKE) OPTIMIZATION=""

.PHONY: all clean dep install 32bit gprof gcov noopt
