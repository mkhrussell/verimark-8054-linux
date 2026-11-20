#!/usr/bin/env bash
# Non-destructive fprintd integration for Kensington VeriMark IT (047d:8054).
#
# Run with sudo from the repository root. This does NOT replace the system
# libfprint or fprintd binaries; it only adds a systemd drop-in that points
# fprintd at our locally built libfprint and preloads a small preseed shim.
# Windows Hello is untouched: the shim injects Windows' own pairing key via
# the public fp_device_set_persistent_data() API, so no PAIR is ever sent.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/fprint-8054
LIBDIR="$PREFIX/lib"
PRESEED=/etc/fprint/8054-preseed.bin
DROPIN=/etc/systemd/system/fprintd.service.d/override.conf

echo "== 1/4: install local libfprint + preseed shim into $LIBDIR =="
install -d -m 755 "$LIBDIR"
install -m 644 "$REPO/build/libfprint/libfprint-2.so.2.0.0" "$LIBDIR/"
ln -sfn libfprint-2.so.2.0.0 "$LIBDIR/libfprint-2.so.2"
ln -sfn libfprint-2.so.2 "$LIBDIR/libfprint-2.so"
install -m 644 "$REPO/tools/preseed_shim.so" "$LIBDIR/libpreseed_shim.so"

echo "== 2/4: install Windows-derived preseed (root-only) =="
install -d -m 700 /etc/fprint
install -m 600 -o root -g root "$REPO/Windows/8054-preseed.bin" "$PRESEED"

echo "== 3/4: fprintd systemd drop-in =="
install -d -m 755 "$(dirname "$DROPIN")"
cat > "$DROPIN" <<'EOF'
[Service]
Environment=LD_LIBRARY_PATH=/opt/fprint-8054/lib
Environment=LD_PRELOAD=/opt/fprint-8054/lib/libpreseed_shim.so
EOF
systemctl daemon-reload

# Guard against exactly the mistake that broke the first install.
test -r "$LIBDIR/libpreseed_shim.so" || {
  echo "FATAL: $LIBDIR/libpreseed_shim.so missing; LD_PRELOAD would be ignored" >&2
  exit 1
}
grep -q "LD_PRELOAD=$LIBDIR/libpreseed_shim.so" "$DROPIN" || {
  echo "FATAL: drop-in LD_PRELOAD path does not match installed shim" >&2
  exit 1
}

echo "== 3b/4: restart fprintd so the new environment takes effect =="
systemctl restart fprintd

echo "== 4/4: enable PAM fingerprint authentication =="
if [ ! -f /etc/pam.d/common-auth.fprint-backup ]; then
  cp -a /etc/pam.d/common-auth /etc/pam.d/common-auth.fprint-backup
fi
DEBIAN_FRONTEND=noninteractive pam-auth-update --force --enable fprintd

# Fallback: some debconf setups still skip the write. Insert the exact line
# from /usr/share/pam-configs/fprintd ahead of pam_unix if needed.
if ! grep -q 'pam_fprintd' /etc/pam.d/common-auth; then
  echo "pam-auth-update did not write the rule; inserting it directly"
  sed -i '/pam_unix\.so/i auth\t[success=end default=ignore]\tpam_fprintd.so max-tries=1 timeout=10' \
    /etc/pam.d/common-auth
fi

echo
echo "== installed =="
grep -n 'pam_fprintd' /etc/pam.d/common-auth
echo
echo "Next steps (run as your normal user, from the repo root):"
echo "  1) free one sensor slot:  LD_LIBRARY_PATH=build/libfprint ./tools/fp_8054 Windows/8054-preseed.bin delete"
echo "  2) enroll:                fprintd-enroll -f left-index-finger \$USER"
echo "  3) verify:                fprintd-verify -f left-index-finger \$USER"
echo "  4) check daemon log:      journalctl -u fprintd -b | grep preseed-shim"
