#!/usr/bin/env bash
# Revert the fprintd integration installed by install_ubuntu.sh.
# Run with sudo. Leaves Windows Hello and on-device templates untouched.
set -euo pipefail

echo "== remove systemd drop-in =="
rm -f /etc/systemd/system/fprintd.service.d/override.conf
rmdir /etc/systemd/system/fprintd.service.d 2>/dev/null || true
systemctl daemon-reload

echo "== restore PAM config =="
if [ -f /etc/pam.d/common-auth.fprint-backup ]; then
  cp -a /etc/pam.d/common-auth.fprint-backup /etc/pam.d/common-auth
  rm -f /etc/pam.d/common-auth.fprint-backup
else
  DEBIAN_FRONTEND=noninteractive pam-auth-update --force --disable fprintd
fi

echo "== remove installed files =="
rm -rf /opt/fprint-8054
rm -f /etc/fprint/8054-preseed.bin
rmdir /etc/fprint 2>/dev/null || true

echo
echo "Reverted. System libfprint and fprintd were never modified."
