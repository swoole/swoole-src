#!/bin/bash

__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

cpp_files=$(git status --porcelain | grep '^[ M]' | grep '\.\(cc\|cpp\|h\)$' | awk '{print $2}')
php_files=$(git status --porcelain | grep '^[ M]' | grep '\.\(php\|phpt\)$' | awk '{print $2}')

if [ -z "$cpp_files" ] && [ -z "$php_files" ]; then
    echo "No files to format."
    exit 0
fi

# 格式化 C/C++ 文件
if [ ! -z "$cpp_files" ]; then
    echo "Formatting C/C++ files..."
    for file in $cpp_files; do
        echo "  - $file"
        clang-format -i "$file"
    done
fi

# 格式化 PHP 和 PHPT 文件
if [ ! -z "$php_files" ]; then
    echo "Formatting PHP files..."
    for file in $php_files; do
        echo "  - $file"
        "$__DIR__"/../tests/include/lib/vendor/bin/php-cs-fixer fix "$file"
    done
fi

echo "✅ Formatting completed successfully!"
