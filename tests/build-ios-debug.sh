#!/bin/bash
# Build only the device debug slice. Existing objects and other XCFramework
# slices are untouched. Pass --install to back up and replace the device slice.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# -gt 1 || (${1:-} != "" && ${1:-} != --install) ]]; then
    echo 'Usage: bash tests/build-ios-debug.sh [--install]' >&2
    exit 2
fi
build_parent="${DF_HEV_BUILD_ROOT:-$HOME/Library/Developer/DigitalFriction}"
mkdir -p "$build_parent"
stage="$(mktemp -d "$build_parent/hev-ios.XXXXXX")"
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
flags="-target arm64-apple-ios15.0 -isysroot $sdk -g -O0"
printf 'Persistent debug build and backup: %s\n' "$stage"
build_part() {
    local name="$1" dir="$2"
    shift 2
    if ! make -j4 -C "$dir" \
        PP="xcrun --sdk iphoneos clang" CC="xcrun --sdk iphoneos clang" \
        AR="xcrun --sdk iphoneos ar" CFLAGS="$flags" \
        BINDIR="$stage/$name/bin" BUILDDIR="$stage/$name/build" \
        "$@" static > "$stage/$name.log" 2>&1; then
        tail -60 "$stage/$name.log" >&2
        exit 1
    fi
    printf 'Built %s\n' "$name"
}
build_part lwip third-part/lwip
build_part yaml third-part/yaml
build_part task third-part/hev-task-system ENABLE_STACK_OVERFLOW_DETECTOR=1
build_part tunnel . -o tp-static
xcrun libtool -static -o "$stage/libhev-socks5-tunnel.a" \
    "$stage/tunnel/bin/libhev-socks5-tunnel.a" \
    "$stage/lwip/bin/liblwip.a" "$stage/yaml/bin/libyaml.a" \
    "$stage/task/bin/libhev-task-system.a"
xcrun lipo -info "$stage/libhev-socks5-tunnel.a"
if [[ ${1:-} == --install ]]; then
    target="HevSocks5Tunnel.xcframework/ios-arm64/libhev-socks5-tunnel.a"
    cp -p "$target" "$stage/previous-ios-arm64.a"
    cp "$stage/libhev-socks5-tunnel.a" "$target"
    cmp "$stage/libhev-socks5-tunnel.a" "$target"
    printf 'Installed device slice. Rollback copy: %s/previous-ios-arm64.a\n' "$stage"
fi
