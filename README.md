# Kensington VeriMark IT (`047d:8054`) on Linux

Working fingerprint authentication on Ubuntu for the **Kensington VeriMark IT**
(`047d:8054`), a Synaptics Tudor Match-in-Sensor reader — **without breaking
Windows Hello**.

Status: **verified working** on Ubuntu 26.04 LTS (fprintd 1.94.5). Enroll,
`fprintd-verify`, PAM (`sudo`, GDM, lock screen) all work; the Windows pairing is
reused rather than replaced.

## How it works

The kernel has no driver for this device. The [`vojtapl/libfprint`](https://github.com/vojtapl/libfprint)
fork contains a `synatlsmoc` driver that knows the PID, but it needs the host
pairing key that Windows created. We recover that key **offline** from the
mounted Windows hives (DPAPI), build a libfprint "preseed" blob, and inject it
into both our helper tools and `fprintd` through the public
`fp_device_set_persistent_data()` API. No PAIR is sent from Linux, so Windows
Hello keeps working.

Nothing under `/usr` is replaced: the fork and shim live in `/opt/fprint-8054`,
selected by a systemd drop-in for `fprintd`.

```
Windows registry blob ──offline DPAPI──▶ preseed ─┬─▶ tools/fp_8054
                                                  └─▶ fprintd (LD_PRELOAD shim)
                                                        │
                                                  PAM / fprintd
```

## Documentation

- **[BUILD_AND_INSTALL.md](BUILD_AND_INSTALL.md)** — full reproducible build
  and installation guide, start to finish.
- **[FINDINGS.md](FINDINGS.md)** — reverse-engineering details, verified
  observations, root-cause analysis, and safety notes.
- **[docs/windows-pairing-migration.md](docs/windows-pairing-migration.md)** —
  pairing-key capture, DPAPI/TagVal format, preseed recipe.

Need a clean slate instead of preserving the existing pairing? See
**[BUILD_AND_INSTALL.md §14](BUILD_AND_INSTALL.md#14-factory-reset-erase-and-re-enroll)**
for the optional, destructive erase-and-re-enroll runbook.

## Contents

```
tools/
  fp_8054.c            enroll/verify/list/save/delete helper
  preseed_shim.c       LD_PRELOAD injection into fprintd
  install_ubuntu.sh    non-destructive system integration
  uninstall_ubuntu.sh  full revert
  verimark-erase.ps1   optional: vendor IOCTL to erase ALL on-device templates
  pairing/             Windows extraction + offline DPAPI tools
```

The official Synaptics driver package (driver 6.0.25.1123) is **not** included
— it contains proprietary DLLs. See Kensington's
[VeriMark IT Setup Guide](https://www.kensington.com/software/verimark-setup/verimark-it-setup-guide/)
or download the [signed driver package](https://www.kensington.com/siteassets/software-support/verimark/2026/kensington-123_v6_0_25_1123_signed_arm64_uwp_x64_inf_1775684104.zip)
directly, then force-install it before using the erase script.

`tools/verimark-erase.ps1` comes from
[Dragonstone787/verimark-it-reset](https://github.com/Dragonstone787/verimark-it-reset)
and is included with attribution.

## Quick start (summary only — see the full guide)

```bash
# build the driver fork
meson setup build reference/libfprint-vojtapl \
  -Dudev_rules=disabled -Dudev_hwdb=disabled -Ddoc=false -Dgtk-examples=false
ninja -C build
./tools/build.sh

# validate the recovered Windows key before any enroll
LD_LIBRARY_PATH=build/libfprint ./tools/pairing/test_open Windows/8054-preseed.bin

# install + enroll
sudo bash tools/install_ubuntu.sh
fprintd-enroll -f left-index-finger "$USER"
fprintd-verify -f left-index-finger "$USER"
```

## Safety

- Never run `clear_storage`, set `SYNATLSMOC_DELETE_ALL_TEMPLATES=1`, or pair
  from Linux without the preseed — the sensor has only 10 template slots and
  Windows owns some of them.
- `Windows/` and all `*.bin` / `*.print` files are **private** and gitignored.
  They contain key material. Never publish them.
- System libfprint/fprintd binaries are never modified; `uninstall_ubuntu.sh`
  reverts the integration.

## License

LGPL-2.1+ to match the libfprint driver ecosystem. See [COPYING](COPYING).
The upstream projects under `reference/` keep their own licenses.
