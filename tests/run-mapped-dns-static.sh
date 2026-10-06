#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_build="$(mktemp -d /tmp/df-hev-dns-static.XXXXXX)"
printf 'Test build: %s\n' "$test_build"
extra_flags=()
if [[ "${SANITIZE:-0}" == 1 ]]; then
    extra_flags=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
xcrun clang -std=c11 -g -O1 -Wall -Wextra -Werror "${extra_flags[@]}" \
    -I src tests/mapped-dns-static.c src/hev-mapped-dns-static.c \
    -o "$test_build/mapped-dns-static"
"$test_build/mapped-dns-static"
