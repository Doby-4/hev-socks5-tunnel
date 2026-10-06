#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_build="$(mktemp -d /tmp/df-hev-dns-runtime.XXXXXX)"
printf 'Test build: %s\n' "$test_build"
extra_flags=()
if [[ "${SANITIZE:-0}" == 1 ]]; then
    extra_flags=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
build_support() {
    local name="$1" dir="$2"
    shift 2
    if ! make -j4 -C "$dir" PP="xcrun clang" CC="xcrun clang" AR="xcrun ar" \
        CFLAGS="-g -O0 ${extra_flags[*]}" BINDIR="$test_build/$name/bin" BUILDDIR="$test_build/$name/build" \
        "$@" static > "$test_build/$name.log" 2>&1; then
        tail -50 "$test_build/$name.log" >&2
        exit 1
    fi
}
build_support yaml third-part/yaml
build_support task third-part/hev-task-system ENABLE_STACK_OVERFLOW_DETECTOR=1
build_support lwip third-part/lwip
build_support tunnel . -o tp-static
xcrun clang -g -O0 -Wall -Wextra -Wno-unused-parameter "${extra_flags[@]}" \
    -I src -I src/misc -I src/core/include -I third-part/hev-task-system/include \
    -I third-part/lwip/src/include -I third-part/lwip/src/ports/include \
    tests/mapped-dns-runtime.c "$test_build/tunnel/bin/libhev-socks5-tunnel.a" \
    "$test_build/lwip/bin/liblwip.a" "$test_build/yaml/bin/libyaml.a" \
    "$test_build/task/bin/libhev-task-system.a" -o "$test_build/mapped-dns-runtime"
"$test_build/mapped-dns-runtime"
