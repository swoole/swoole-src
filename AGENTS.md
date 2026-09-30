# Repository Guidelines

## Project Structure & Module Organization

`src/` and `include/` contain the C++ core. `ext-src/` implements the PHP extension and its bindings; `library/` contains bundled PHP code. PHP regression tests live in `tests/` as `.phpt` files, grouped by feature (for example, `tests/swoole_http_server/`). C++ GoogleTest cases live in `core-tests/`. Look in `examples/` for runnable samples, `docs/` for development notes, and `thirdparty/` for vendored dependencies.

## Build, Test, and Development Commands

- `phpize && ./configure && make -j$(nproc)` builds the PHP extension in `modules/swoole.so`. Run `./configure --help` for optional integrations such as sockets and curl.
- `PHPT=1 php -n run-tests.php -n -d extension=modules/swoole.so tests/swoole_http_server/create_request_large_upgrade.phpt` runs one PHP regression test. Pass a directory instead of a file to run that suite.
- `cmake . && make -j$(nproc) core-tests` builds the C++ tests; `./bin/core-tests --gtest_filter=server.*` runs a selected group. Some tests require services described in `docs/TESTS.md`.

## Coding Style & Naming Conventions

Use four spaces in C, C++, PHP, and PHPT files, LF line endings, and a final newline, as specified by `.editorconfig`. Keep C++ changes consistent with `.clang-format` (120-column limit); format touched C++ code with `clang-format`. Follow the repository's PHP style configuration in `.php-cs-fixer.dist.php`; `./php-cs-fix <path>` formats PHP files when its Composer dependencies are installed. Name PHPT files after the behavior they cover and place them beside related tests.

## Testing Guidelines

Add a focused `.phpt` regression for PHP-visible fixes and a GoogleTest case for core-only behavior. Include boundary and fragmented-input cases for parsers. Run the new test and nearby existing tests against the freshly built extension. Tests involving databases, Redis, or network services need their fixtures available; check `tests/include/` and `docs/TESTS.md` before running a broad suite.

## Commit & Pull Request Guidelines

Use a short, imperative subject. Recent commits commonly use a scope such as `fix(http): ...` or `test(socket): ...`; include an issue or PR number when applicable. In pull requests, explain the bug or behavior change, list the tests run, and link the relevant issue. Keep release branches `6.1` and `6.2` limited to bug fixes; verify a backport on each target branch before pushing.
