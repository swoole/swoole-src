#!/bin/sh

case "${SSH_ORIGINAL_COMMAND:-}" in
    'scp -pf '*) ;;
    *) exit 1 ;;
esac

dd bs=1 count=1 of=/dev/null 2>/dev/null
printf 'T0 0 0 0\n'
dd bs=1 count=1 of=/dev/null 2>/dev/null
printf 'C0644 10 truncated.txt\n'
dd bs=1 count=1 of=/dev/null 2>/dev/null
printf 'abc'
