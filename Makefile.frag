swoole-build-coverage:
	CCACHE_DISABLE=1 EXTRA_CFLAGS="-fprofile-arcs -ftest-coverage" EXTRA_CXXFLAGS="-fprofile-arcs -ftest-coverage" $(MAKE)

swoole-test-coverage:
	CCACHE_DISABLE=1 EXTRA_CFLAGS="-fprofile-arcs -ftest-coverage" EXTRA_CXXFLAGS="-fprofile-arcs -ftest-coverage" $(MAKE) && $(MAKE) install && $(top_srcdir)/tests/start.sh $(top_srcdir)/tests

swoole-test-coverage-lcov: swoole-test-coverage
	lcov -c --directory $(top_srcdir)/.libs --output-file $(top_srcdir)/coverage.info

swoole-test-coverage-html: swoole-test-coverage-lcov
	genhtml $(top_srcdir)/coverage.info --output-directory=$(top_srcdir)/html
