#!/usr/bin/env bash
# Rebuild the local libfprint helper tools against build/libfprint.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"
CFLAGS_COMMON="-I$REPO/reference/libfprint-vojtapl -I$REPO/reference/libfprint-vojtapl/libfprint -I$REPO/build/libfprint $(pkg-config --cflags glib-2.0 gio-unix-2.0 gusb)"
LDFLAGS_COMMON="-L$REPO/build/libfprint -lfprint-2 $(pkg-config --libs glib-2.0 gio-unix-2.0 gusb) -Wl,-rpath,$REPO/build/libfprint"

build() {
  local src="$1" out="${1%.c}"
  echo "building $out"
  gcc -o "$out" "$src" $CFLAGS_COMMON $LDFLAGS_COMMON
}

build tools/list_devices.c
build tools/probe_version.c
build tools/pairing/test_open.c
build tools/fp_8054.c

# LD_PRELOAD shim for fprintd. rpath $ORIGIN lets it find our libfprint when
# both are installed side by side in /opt/fprint-8054/lib.
echo "building tools/preseed_shim.so"
gcc -shared -fPIC -o tools/preseed_shim.so tools/preseed_shim.c \
  $CFLAGS_COMMON -ldl \
  -L$REPO/build/libfprint -lfprint-2 \
  $(pkg-config --libs glib-2.0 gio-2.0) \
  -Wl,-rpath,'$ORIGIN'
echo done
