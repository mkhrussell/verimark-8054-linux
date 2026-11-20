# Kensington VeriMark IT (`047d:8054`) — build & install guide

A complete, reproducible walkthrough for building the Synaptics Tudor Match-in-Sensor
(`synatlsmoc`) driver on Linux and enabling fingerprint login through `fprintd`/PAM,
**while preserving Windows Hello**.

Verified on Ubuntu 26.04 LTS, kernel 6.x, `fprintd 1.94.5`,
`libfprint-2-2 1.95.1+tod1`. Sensor: firmware 10.1, MIS serial `<MIS_SERIAL>`.

---

## Table of contents

0. [Read this first — safety rules](#0-read-this-first--safety-rules)
1. [How it fits together](#1-how-it-fits-together)
2. [Prerequisites](#2-prerequisites)
3. [Get the source](#3-get-the-source)
4. [Build libfprint locally](#4-build-libfprint-locally)
5. [Device access (udev)](#5-device-access-udev)
6. [Recover the Windows pairing key (read-only)](#6-recover-the-windows-pairing-key-read-only)
7. [Build the helper tools](#7-build-the-helper-tools)
8. [Validate before installing](#8-validate-before-installing)
9. [Install for fprintd + PAM](#9-install-for-fprintd--pam)
10. [Enroll and verify](#10-enroll-and-verify)
11. [Verification checklist](#11-verification-checklist)
12. [Troubleshooting](#12-troubleshooting)
13. [Uninstall / revert](#13-uninstall--revert)
14. [Factory reset: erase and re-enroll](#14-factory-reset-erase-and-re-enroll)
15. [File inventory](#15-file-inventory)

---

## 0. Read this first — safety rules

These are hard constraints learned the hard way. Violating them can destroy your
Windows Hello fingerprints.

1. **Never *accidentally* wipe the template store.** Do not rely on
   `clear_storage`, fprintd's first-enrollment cleanup, or
   `SYNATLSMOC_DELETE_ALL_TEMPLATES=1` — all are blunt and can destroy the
   Windows fingerprints. The sensor has **10 slots** and no backup. If you
   genuinely want a clean slate, use the deliberate, informed procedure in
   [§14 Factory reset](#14-factory-reset-erase-and-re-enroll), then re-enroll
   **both** operating systems.
2. **Never let the sensor PAIR from Linux without the preseed.** A fresh PAIR
   overwrites the Windows pairing. Every tool here injects the Windows-derived
   pairing data through `fp_device_set_persistent_data()` before opening.
3. **Never write to the Windows partition.** Mount it read-only (`-o ro`).
4. **Keep private material local and mode `600`:**
   `Windows/plain.bin`, `Windows/8054-preseed.bin`, `Windows/pairing-fields.json`.
   **Never commit or upload these** — they contain the host private key.
5. **Do not replace system libfprint/fprintd.** Everything is installed under
   `/opt/fprint-8054` and pointed at via a systemd drop-in.
6. Keep a Windows boot available until you have re-confirmed Hello at the end.

---

## 1. How it fits together

```
Windows registry (DPAPI blob)
        │  offline, read-only
        ▼
plain.bin ──make_preseed.py──▶ 8054-preseed.bin  (GVariant "(issv)", 1082 B)
        │
        ├─▶ tools/fp_8054            (manual enroll/verify/list/delete)
        └─▶ tools/preseed_shim.so    (LD_PRELOAD into fprintd)
                                       │
                    fprintd ───────────┘  +  LD_LIBRARY_PATH=our libfprint
                       │
                    PAM (pam_fprintd) → sudo, GDM, lock screen
```

- `vojtapl/libfprint` is a libfprint 1.94.9 fork whose `synatlsmoc` driver already
  lists `047d:8054`. It is built locally; the system library is untouched.
- `fp_device_set_persistent_data()` is **in-process only** — it does not write to
  disk. The `LD_PRELOAD` shim hooks `FpContext::device-added` and injects the
  preseed whenever fprintd enumerates devices, so no PAIR is ever sent.
- This avoids patching/rebuilding fprintd (the alternative is the fprintd
  persistent-data patch in `vojtapl/synaTudorMiS`).

---

## 2. Prerequisites

```bash
sudo apt update
sudo apt install -y \
  build-essential meson ninja-build pkg-config git \
  libglib2.0-dev libgusb-dev libusb-1.0-0-dev libssl-dev \
  python3 python3-pip python3-gi python3-pycryptodome python3-cryptography \
  fprintd libpam-fprintd
```

Notes:
- `python3-pycryptodome` provides the `Cryptodome` namespace.
- `impacket` is **vendored** in `reference/impacket`; no pip install needed.
- `libfprint-2-tod1` may remain installed; our override takes precedence.

Make a workspace:

```bash
mkdir -p ~/Developer/FingerPrint
cd ~/Developer/FingerPrint
```

---

## 3. Get the source

Two repositories:

```bash
# 1) The driver fork (upstream — read only, do not modify or push)
git clone https://github.com/vojtapl/libfprint.git libfprint-vojtapl
cd libfprint-vojtapl
git checkout 0c67248a5a4af188d6c1417fb348f655e80f6c8e   # pinned, verified commit
cd ..

# 2) This project (tools, scripts, docs)
git clone https://github.com/<YOUR-USER>/verimark-8054-linux.git FingerprintDeiverReverseEng
cd FingerprintDeiverReverseEng
```

If you are rebuilding from this guide before the GitHub repo exists, place the
`tools/`, `docs/`, `FINDINGS.md` and `BUILD_AND_INSTALL.md` files in
`FingerprintDeiverReverseEng/` manually, then move the fork to
`reference/libfprint-vojtapl`:

```bash
mkdir -p reference
mv ../libfprint-vojtapl reference/
```

Vendored impacket (needed only for key recovery):

```bash
mkdir -p reference
git clone --depth 1 https://github.com/fortra/impacket.git reference/impacket
```

Final layout:

```
FingerprintDeiverReverseEng/
├── BUILD_AND_INSTALL.md
├── FINDINGS.md
├── docs/windows-pairing-migration.md
├── tools/                     # our code
├── reference/
│   ├── libfprint-vojtapl/     # driver fork (read-only)
│   └── impacket/              # low-level DPAPI helpers (read-only)
├── Windows/                   # PRIVATE — never commit
└── build/                     # generated
```

---

## 4. Build libfprint locally

```bash
cd ~/Developer/FingerPrint/FingerprintDeiverReverseEng
meson setup build reference/libfprint-vojtapl \
  -Dudev_rules=disabled -Dudev_hwdb=disabled \
  -Ddoc=false -Dgtk-examples=false
ninja -C build
```

`-Dudev_rules=disabled -Dudev_hwdb=disabled` works around a distro `udev` pkg-config
quirk. The resulting library is:

```
build/libfprint/libfprint-2.so.2.0.0     (soname libfprint-2.so.2)
```

Sanity check — it must export the persistent-data API:

```bash
nm -D build/libfprint/libfprint-2.so.2.0.0 | grep fp_device_set_persistent_data
# 0000000000019490 T fp_device_set_persistent_data@@LIBFPRINT_2.0.0
```

No `meson install` — nothing is written to `/usr`.

---

## 5. Device access (udev)

Plug in the reader, then find your IDs:

```bash
lsusb | grep -i 047d        # expect: ID 047d:8054
```

Install a rule so your user can open the USB node without root:

```bash
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="047d", ATTR{idProduct}=="8054", OWNER="'"$USER"'", MODE="0600"' \
  | sudo tee /etc/udev/rules.d/99-verimark.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Re-plug and confirm the node is owned by you.

---

## 6. Recover the Windows pairing key (read-only)

This is the critical step that makes Windows Hello survive. Do it **before** any
Linux enroll.

> **Fill in your own identifiers first.** This repo deliberately ships
> placeholders, not machine-specific values:
>
> - In `tools/pairing/extract-8054-minimal.ps1`, replace `<USB_SERIAL>` with the
>   value from `lsusb -d 047d:8054 -v | grep iSerial`, and `<MIS_SERIAL_HEX>`
>   with the 6-byte GET_VERSION serial (bytes 18:24) plus `0000`.
> - In your shell, `export WINROOT=/run/media/$USER/Win11Pro`.
> - Optional: `export MIS_SERIAL=<your-mis-serial-hex>` (metadata only).
>
> The DPAPI master-key GUID needs no configuration — `offline_decrypt.py` tries
> every master key in the LOCAL SERVICE store automatically.

### 6.1 Windows: export the registry value

Run PowerShell **elevated**:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pairing\extract-8054-minimal.ps1
```

It reads (without modifying):
`HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_047D&PID_8054\<serial>\Device Parameters\synaWudfBioUsb123`
→ value named after the uppercase MIS serial (e.g. `<MIS_SERIAL_HEX>`).

It writes `Windows/Device-USB-Info.reg` and a decrypted `plain.bin` if it can.
If the automatic decryption path fails, export the registry key manually with
`reg export` and continue on Linux.

**Never** run unpair/reset/clear scripts. Reading the value is harmless.

### 6.2 Linux: mount Windows read-only

```bash
sudo mkdir -p /run/media/$USER/Win11Pro
sudo mount -o ro /dev/nvmeXn1pY /run/media/$USER/Win11Pro   # adjust device
```

Strip the 16-byte Synaptics wrapper from the 1788-byte registry value to obtain
the raw DPAPI blob (e.g. with Python; keep it under `/tmp`, not in the repo).

### 6.3 Decrypt offline

```bash
python3 tools/pairing/offline_decrypt.py \
  /run/media/$USER/Win11Pro \
  /tmp/8054-dpapi.bin
```

It derives the boot key from `SYSTEM`, the LSA key from `SECURITY`, the
`DPAPI_SYSTEM` keys, decrypts master key
`<DPAPI_MASTER_KEY_GUID>` and the blob, then writes:

```
Windows/plain.bin            (1284-byte TagVal container)
Windows/pairing-fields.json
```

### 6.4 Build the preseed

```bash
python3 tools/pairing/make_preseed.py Windows/plain.bin Windows/8054-preseed.bin
chmod 600 Windows/8054-preseed.bin
```

The script verifies the sensor certificate against `pubkey_v10_1_kf` (FW 10.1)
and checks the private key matches the host certificate. Expected size: **1082
bytes**.

### 6.5 Validate the key (no writes to the sensor)

```bash
LD_LIBRARY_PATH=build/libfprint G_MESSAGES_DEBUG=all \
  ./tools/pairing/test_open Windows/8054-preseed.bin
```

Success looks like:

```
=== OPEN SUCCEEDED: TLS session established with preseeded key ===
```

If you see `Need to pair sensor` or TLS `bad certificate`, **stop** — do not
enroll. Recheck the serial/decryption steps.

---

## 7. Build the helper tools

```bash
./tools/build.sh
```

This produces against the local library:

| Binary | Purpose |
| --- | --- |
| `tools/list_devices` | confirm driver detects `047d:8054` |
| `tools/probe_version` | read-only GET_VERSION probe |
| `tools/pairing/test_open` | preseed validation (open only) |
| `tools/fp_8054` | enroll / verify / list / save / delete |
| `tools/preseed_shim.so` | LD_PRELOAD shim for fprintd |

Quick check:

```bash
LD_LIBRARY_PATH=build/libfprint ./tools/list_devices
# should report driver=synatlsmoc id=0
```

---

## 8. Validate before installing

Inspect the on-device slots (read-only):

```bash
LD_LIBRARY_PATH=build/libfprint \
  ./tools/fp_8054 Windows/8054-preseed.bin list
```

Interpretation:

- `desc=Template without enrollment data` → **Windows template**. The driver
  refuses to delete these (`synatlsmoc.c:4373-4382`). Leave them alone.
- Any other description with a user-ID payload → a **Linux-created** template.
  Remove stale ones with `delete-linux [slot]` before enrolling so the 10-slot
  store is not full:

```bash
# delete highest slot first; indices shift after each deletion
LD_LIBRARY_PATH=build/libfprint ./tools/fp_8054 Windows/8054-preseed.bin delete-linux 9
LD_LIBRARY_PATH=build/libfprint ./tools/fp_8054 Windows/8054-preseed.bin list
```

Do **not** use `delete` for a template that is not your own `FP1-*-nobody` marker;
the tool will refuse anyway.

---

## 9. Install for fprintd + PAM

Review, then run:

```bash
sed -n '1,200p' tools/install_ubuntu.sh
sudo bash tools/install_ubuntu.sh
```

The script:

1. copies `build/libfprint/libfprint-2.so.2.0.0` and `preseed_shim.so` (as
   `libpreseed_shim.so`) to `/opt/fprint-8054/lib`;
2. installs the preseed to `/etc/fprint/8054-preseed.bin` (`root:root 0600`);
3. writes `/etc/systemd/system/fprintd.service.d/override.conf`:

   ```ini
   [Service]
   Environment=LD_LIBRARY_PATH=/opt/fprint-8054/lib
   Environment=LD_PRELOAD=/opt/fprint-8054/lib/libpreseed_shim.so
   ```

4. runs `systemctl daemon-reload` and restarts fprintd;
5. enables the PAM profile via `pam-auth-update --force --enable fprintd`
   (with a direct-insert fallback into `/etc/pam.d/common-auth`).

System libfprint and fprintd binaries are **never** replaced.

> If fprintd was previously installed with a broken `LD_PRELOAD` path, re-running
> this corrected script fixes it and fails fast if the paths disagree.

---

## 10. Enroll and verify

```bash
fprintd-enroll -f left-index-finger "$USER"
fprintd-verify -f left-index-finger "$USER"
fprintd-list "$USER"
```

Touch the sensor for each of the 8 enrollment stages. Expected:

```
Enroll result: enroll-completed
Verify result: verify-match (done)
Fingerprints for user <you> on Synaptics Tudor Match-In-Sensor (press):
 - #0: left-index-finger
```

Confirm the shim is active:

```bash
sudo journalctl -u fprintd -b --no-pager | grep -i preseed-shim
```

Expected:

```
preseed-shim: hooked FpContext::device-added (preseed /etc/fprint/8054-preseed.bin)
preseed-shim: injected 1082 bytes ... into synatlsmoc device 0
```

Test PAM:

```bash
sudo -k && sudo true          # touch sensor when prompted
# also lock/unlock the desktop and try GDM
```

The PAM rule is `[success=end default=ignore]`, so any fingerprint failure falls
back to your password — you cannot be locked out.

---

## 11. Verification checklist

- [ ] `tools/pairing/test_open` → `OPEN SUCCEEDED`, no PAIR / bad certificate
- [ ] `tools/fp_8054 ... list` shows Windows templates still present
- [ ] `fprintd-enroll` → `enroll-completed`
- [ ] `fprintd-verify` → `verify-match`
- [ ] `fprintd-list "$USER"` lists the finger
- [ ] journal shows both `preseed-shim` lines on each fprintd start
- [ ] `sudo systemctl restart fprintd` then `fprintd-verify` still matches
- [ ] PAM works (`sudo`, lock screen, GDM)
- [ ] **Boot Windows and confirm Hello still verifies**

---

## 12. Troubleshooting

**`verify-no-match`, then `NoEnrolledPrints` on later commands.**
fprintd's `check_local_storage()` deleted the print file because the device was
opened without the preseed (fresh PAIR). Check the journal for `preseed-shim`
lines; verify `/opt/fprint-8054/lib/libpreseed_shim.so` exists and matches the
drop-in. Fix: re-run `sudo bash tools/install_ubuntu.sh`, remove stale Linux
templates, re-enroll.

**`Need to pair sensor` / TLS `bad certificate`.**
The preseed is wrong or the Windows pairing was overwritten. Re-extract the DPAPI
blob and regenerate the preseed. Do not enroll until `test_open` succeeds.

**`VCS_RESULT_DB_FULL` on enroll.**
All 10 slots are used. Remove only Linux-owned templates with `delete-linux`
(highest slot first), never Windows ones. If the store is entirely stale or you
want a clean start, use [§14](#14-factory-reset-erase-and-re-enroll) instead.

**fprintd reports a different device name.**
`Synaptics Tudor Match-In-Sensor` is our fork. Any other name means
`LD_LIBRARY_PATH` is not being applied — check the drop-in and `systemctl cat
fprintd`.

**Device node permission denied.**
Recheck the udev rule and re-plug. `ls -l /dev/bus/usb/*/*` should show your user.

**Enroll crashes with SIGSEGV.**
Already fixed in this tree: `FpPrint` is floating; do not wrap the enrollment
template in `g_autoptr`. Rebuild from the pinned sources.

---

## 13. Uninstall / revert

```bash
sudo bash tools/uninstall_ubuntu.sh
```

It removes the drop-in, restores `/etc/pam.d/common-auth` from the backup, and
deletes `/opt/fprint-8054` and `/etc/fprint/8054-preseed.bin`. Windows templates
and on-device prints are never touched. The locally built library stays in
`build/` for experimentation.

---

## 14. Factory reset: erase and re-enroll

Use this only when you deliberately want to throw away **all** fingerprints on
the sensor — e.g. the store is full of stale templates you cannot identify, or
you want both operating systems to start from a clean slate.

This is more predictable than relying on libfprint's `clear_storage` or the
`SYNATLSMOC_DELETE_ALL_TEMPLATES` debug switch. It uses the vendor's own
`EraseDatabase` IOCTL, discovered by disassembling `CBiometricDevice::
OnEraseDatabase` in `synaWudfBioUsb123.dll`, and it requires an intentional,
confirmed action in Windows. It still deletes every template; it is not a
backup or a repair operation.

`tools/verimark-erase.ps1` is imported from
[Dragonstone787/verimark-it-reset](https://github.com/Dragonstone787/verimark-it-reset)
with attribution; the logic is unchanged from upstream. The upstream repository
had no `LICENSE` file when checked on 2026-11-20, so review its terms before
redistributing the script.

### 14.1 Prerequisites

- The official Synaptics driver **6.0.25.1123** must be bound to the sensor.
  Windows may refuse to install it automatically; force it:
  1. Download [Kensington's official driver package](https://www.kensington.com/siteassets/software-support/verimark/2026/kensington-123_v6_0_25_1123_signed_arm64_uwp_x64_inf_1775684104.zip)
     (downloads as `kensington-123_v6_0_25_1123_signed_arm64_uwp_x64_inf_1775684104.zip`;
     referred to below as `Kensington-123_v6_0_25_1123.zip`). It is **not**
     shipped in this repo because it contains proprietary Synaptics DLLs.
  2. Device Manager → **Biometric devices** → right-click the reader →
     **Update driver** → *Browse my computer* → *Let me pick* → **Have Disk** →
     point at the extracted `synaWudfBioUsbUwpOne.inf`.
  3. Reboot if asked. Confirm the version is `6.0.25.1123` in Driver properties.

  Hardware IDs handled by that package: `VID_047D&PID_8054` and
  `VID_06CB&PID_00D6`.

- The script prints the detected driver and refuses to run on an untested
  version unless you pass `-Force`.

### 14.2 Erase

Run in an **Administrator PowerShell**:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\verimark-erase.ps1
```

It will:

1. find the biometric device interface,
2. stop the Windows Biometric Service (`WbioSrvc`),
3. send IOCTL `0x442028` (`EraseDatabase`),
4. restart `WbioSrvc` in a `finally` block.

Confirm with `YES` when prompted. Then:

```text
Unplug the key, wait 5 seconds, plug it back in.
```

All 10 template slots are now empty. **This does not create a backup.**

### 14.3 Re-enroll Windows first

In Windows: **Settings → Accounts → Sign-in options → Fingerprint → Add**.
Enroll the fingers you want Windows Hello to use. Verify Hello works.

Windows may establish a new pairing during this step. If it does, your existing
Linux preseed is stale and must be regenerated — assume this is the case.

### 14.4 Re-enroll Ubuntu

Back in Linux, refresh the pairing key from the freshly enrolled Windows state:

```bash
export WINROOT=/run/media/$USER/Win11Pro

# re-extract the DPAPI blob from Windows (see §6.1), then:
python3 tools/pairing/offline_decrypt.py "$WINROOT" /tmp/8054-dpapi.bin
python3 tools/pairing/make_preseed.py Windows/plain.bin Windows/8054-preseed.bin
chmod 600 Windows/8054-preseed.bin

LD_LIBRARY_PATH=build/libfprint ./tools/pairing/test_open Windows/8054-preseed.bin
```

Do not continue until `test_open` reports `OPEN SUCCEEDED`. Then install the new
preseed and enroll:

```bash
sudo bash tools/install_ubuntu.sh          # refreshes /etc/fprint/8054-preseed.bin
LD_LIBRARY_PATH=build/libfprint ./tools/fp_8054 Windows/8054-preseed.bin list
fprintd-enroll -f left-index-finger "$USER"
fprintd-verify -f left-index-finger "$USER"
```

`list` should now show only the Windows templates you just enrolled. If any
Linux-owned template survived, remove it with `delete-linux [slot]` first.

### 14.5 Confirm both sides

- `fprintd-verify` → `verify-match`
- `sudo -k && sudo true` → fingerprint accepted
- reboot into Windows → Windows Hello still accepts the enrolled fingers

Keep the previous preseed file until the new one is confirmed working.

---

## 15. File inventory

| Path | Committed to GitHub? | Notes |
| --- | --- | --- |
| `tools/*.c`, `tools/*.sh`, `tools/pairing/*.py`, `*.ps1`, `tools/verimark-erase.ps1` | yes | our modifications |
| `docs/`, `FINDINGS.md`, `BUILD_AND_INSTALL.md` | yes | documentation |
| `reference/libfprint-vojtapl` | no | upstream fork, pinned commit |
| `reference/impacket` | no | upstream library |
| `Kensington-123_v6_0_25_1123.zip` | **NO** | proprietary Synaptics DLLs — obtain from vendor |
| `Windows/*` | **NO** | private keys / registry exports |
| `build/*` | no | build output |
| `*.print`, `*.bin`, `*.so`, compiled tools | no | generated / private |

License: the driver fork is LGPL-2.1+; these tools and scripts are provided under
the same license for consistency. See `COPYING`.

---

## References

- https://github.com/vojtapl/libfprint — `synatlsmoc` driver fork
- https://github.com/vojtapl/synaTudorMiS — RE notes and fprintd persistent-data patch
- https://github.com/SShadowS/verimark-linux-driver — clean-room sibling-driver protocol map
- https://github.com/jedbillyb/linux-fingerprint-drivers — device support index
- https://github.com/fortra/impacket — DPAPI/hive parsing
- https://github.com/Dragonstone787/verimark-it-reset — source of `verimark-erase.ps1`
- https://www.kensington.com/siteassets/software-support/verimark/2026/kensington-123_v6_0_25_1123_signed_arm64_uwp_x64_inf_1775684104.zip — official driver 6.0.25.1123
