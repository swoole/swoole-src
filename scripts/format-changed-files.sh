#!/bin/bash

changed_files=$(git status --porcelain | grep '^[ M].*\.cc$' | awk '{print $2}')

if [ -z "$changed_files" ]; then
    exit 0
fi

for file in $changed_files; do
    echo "format $file"
    clang-format -i "$file"
done

echo "done"
