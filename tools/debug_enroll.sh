#!/usr/bin/env bash
# Reproduce the enroll crash under gdb and print a full backtrace.
# Touch the sensor as prompted; when it crashes, the backtrace is printed here.
set -u
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD/build/libfprint${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export G_MESSAGES_DEBUG=all
exec gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'set confirm off' \
  -ex run \
  -ex 'printf "\n===== BACKTRACE =====\n"' \
  -ex 'bt full' \
  --args ./tools/fp_8054 Windows/8054-preseed.bin enroll 2 "$HOME/8054-debug.print" 2>&1 | tee /tmp/opencode/enroll-gdb.log
