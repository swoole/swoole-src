#!/bin/bash

__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

cpp_files=$(git status --porcelain | grep '^[ M]' | grep '\.\(cc\|cpp\|h\)$' | awk '{print $2}')
php_files=$(git status --porcelain | grep '^[ M]' | grep '\.\(php\|phpt\)$' | awk '{print $2}')
arginfo_files=$(git status --porcelain | grep '^[ M]' | grep '_arginfo\.h$' | awk '{print $2}')

if [ -z "$cpp_files" ] && [ -z "$php_files" ]; then
    echo "No files to format."
    exit 0
fi

# 格式化 C/C++ 文件
if [ ! -z "$cpp_files" ]; then
    echo "Formatting C/C++ files..."
    for file in $cpp_files; do
        # 额外检查确保不处理 _arginfo.h 文件
        if [[ "$file" != *_arginfo.h ]]; then
            echo "  - $file"
            clang-format -i "$file"
        fi
    done
fi

# 格式化 PHP 和 PHPT 文件
if [ -n "$php_files" ]; then
    echo "Formatting PHP files..."

    # 过滤掉 .stub.php 文件
    filtered_files=$(echo "$php_files" | grep -v '\.stub\.php$')

    if [ -n "$filtered_files" ]; then
        echo "$filtered_files" | xargs -I {} bash -c '
            file="{}"
            if [ -f "$file" ]; then
                echo "  ✓ Formatting: $file"
                "'"$__DIR__"'/../tests/include/lib/vendor/bin/php-cs-fixer" fix "$file"
            fi
        '
    else
        echo "All files are stub files, skipping."
    fi
fi

# 显示跳过的 _arginfo.h 文件
if [ ! -z "$arginfo_files" ]; then
    echo "Skipped auto-generated files:"
    for file in $arginfo_files; do
        echo "  - $file (auto-generated)"
    done
fi


echo "✅ Formatting completed successfully!"
