# Kensington VeriMark IT (`047d:8054`) — reverse-engineering status

Started 2026-11-19. Workspace was empty; all prior art below was researched and
cloned into `reference/` (read-only — do not edit upstream repos in place).

## 1. The device (live, on this machine)

`lsusb` / sysfs, Bus 001 Device 011, sysfs path `1-2.3.2`:

| Property | Value |
| --- | --- |
| VID:PID | `047d:8054` (Kensington) |
| Serial | `<USB_SERIAL>` |
| USB | 2.00, Full Speed (12 Mbps) |
| Device class | `ff/10/ff` (vendor specific) |
| Configurations / Interfaces | 1 / 1 (`bInterfaceClass 0xff`, subclass 0, protocol 0) |
| Bulk OUT | EP `0x01`, 64 bytes |
| Bulk IN | EP `0x81`, 64 bytes |
| Interrupt IN | EP `0x83`, 8 bytes, interval 4 |
| Driver binding | no standard driver claims the interface |
| Node | `/dev/bus/usb/001/011` (`crw-rw-r--` root:root) — **root required** |

This is a **Synaptics Tudor Match-in-Sensor (MiS)** reader: templates are
created/stored/matched inside the sensor; the host only talks a command protocol
over an encrypted (non-standard TLS 1.2-like) session. Windows driver build for
this PID is `synaWudfBioUsb123.dll` v6.0.25.1123
(`synaWudfBioUsbUwpOne.inf`, build "123", also covers `06cb:00d6`).

Note: the sibling VeriMark **Desktop** (`047d:00f2`) uses EP0 control transfers
("bulk-over-control"). This `8054` device has real bulk endpoints, and Synaptics'
own WinDbg logs show `palWinUsbBulkWrite`/`palWinUsbBulkRead`, so do not assume
the `00f2` transport applies verbatim.

## 2. Prior art (all public, all cloned locally)

| Source | What it is | Relevance to `8054` |
| --- | --- | --- |
| [`vojtapl/synaTudorMiS`](https://github.com/vojtapl/synaTudorMiS) | RE notes, Ghidra exports, WinDbg logs, Python lab driver, Kensington 123 INF | Explicitly lists `047D:8054 (tested)`; contains a `047d:8054`-specific LED_EX2 patch |
| [`vojtapl/libfprint`](https://github.com/vojtapl/libfprint) `main` | libfprint 1.94.9 fork with `synatlsmoc` driver (~7.5k lines) | `id_table` already has `047d:8054` with `SYNATLSMOC_DRIVER_DATA_HAS_LED`. **Best candidate.** |
| [`Popax21/synaTudor`](https://github.com/Popax21/synaTudor) `relink` | Dynamically relinks the Windows DLL at runtime on Linux | Fastest to "something works", but runs proprietary binaries; not a clean-room driver |
| [`SShadowS/verimark-linux-driver`](https://github.com/SShadowS/verimark-linux-driver) | Clean-room libfprint driver for sibling `047d:00f2` | Full protocol map + TLS + pairing; useful reference, different PID/transport |
| [`jedbillyb/linux-fingerprint-drivers`](https://github.com/jedbillyb/linux-fingerprint-drivers) | Community driver index | Confirms `047d:8054` has no upstream fix; gap-map |

## 3. Progress (2026-11-19)

**Done / verified on this machine:**

- Build toolchain + `-dev` libraries installed via apt.
- udev rule active: `OWNER="<your-user>", MODE="0600"` for `047d:8054`; device node
  is writable without root (re-enumerated as `/dev/bus/usb/001/025`).
- `vojtapl/libfprint` 1.94.9 fork built locally at `build/libfprint` with
  `-Dudev_rules=disabled -Dudev_hwdb=disabled -Ddoc=false` (distro `udev` pc-name
  quirk). **No system files replaced.**
- `tools/list_devices` confirms the driver recognises the device:
  `driver=synatlsmoc id=0`.
- **Read-only `GET_VERSION` probe** (`tools/probe_version`) succeeded on bulk
  EPs `0x01`/`0x81`, status `0x0000`, response:

  | Field | Value |
  | --- | --- |
  | firmware | 10.1 |
  | build_time / build_num | 1565744536 / 0x002e426f |
  | product_id / target / silicon_rev | 0x41 / 0x01 / 0x01 |
  | MIS serial (bytes 18:24) | `<MIS_SERIAL>` |
  | security | 0x0b → advanced security bit (0x1) **set** |
  | interface | 0xa1 → keyflag bit (0x20) **set** → `pubkey_v10_1_kf` |
  | provision_state | 3 → `PROVISIONED` |

  This also resolves two open questions in `docs/windows-pairing-migration.md`:
  firmware is 10.1 and the keyflag is TRUE (sensor cert must verify against
  `pubkey_v10_1_kf`). No pairing, enrollment, or reset was sent.

## 4. Pairing key recovered — Windows Hello preserved (verified 2026-11-20)

The original Windows-side extraction script crashed before it ever searched
(bad `icacls` SID format + `$ErrorActionPreference='Stop'`), which is why the
user saw "no Synaptics data". The data was actually in the registry export the
user provided: `Device-USB-Info.reg` contains value `<MIS_SERIAL_HEX>` under
`HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_047D&PID_8054\<serial>\Device
Parameters\synaWudfBioUsb123` — exactly the MIS serial from our GET_VERSION
probe. It is a 1788-byte Synaptics wrapper around an 1772-byte **user-scoped
DPAPI blob** (master key GUID `<DPAPI_MASTER_KEY_GUID>`).

With the Windows partition mounted read-only at `/run/media/<user>/Win11Pro`,
`tools/pairing/offline_decrypt.py` derives the boot key from the SYSTEM hive,
the LSA key from the SECURITY hive, the `DPAPI_SYSTEM` machine/user keys, then
decrypts the master key and the blob **offline** — no Windows boot needed.
Result (`Windows/plain.bin`, 1284 bytes) is a TagVal container:

| Tag | Length | Meaning |
| --- | --- | --- |
| 0x0000 | 2 | unknown/flags |
| 0x0001 | 400 | host certificate (cert_type=2, sign_size=32) |
| 0x0002 | 32 | host EC private key (little-endian P-256 scalar) |
| 0x0003 | 400 | sensor certificate (cert_type=0, sign_size=71) — verifies with `pubkey_v10_1_kf` |
| 0x0004 | 420 | unknown auxiliary data |

`tools/pairing/make_preseed.py` accepts `plain.bin` directly, identifies the
sensor cert (tag 3) by verifying against the FW 10.1 key matching our probe,
checks the private key (tag 2) matches the host cert (tag 1), and emits a
1082-byte `(issv)` persistent-data blob.

**Critical result:** `tools/pairing/test_open` with this real preseed reports
`Open completed successfully` / `OPEN SUCCEEDED: TLS session established with
preseeded key`. There is **no** `Need to pair sensor` and **no** TLS
`bad certificate` alert (the earlier sample-data test failed with exactly that
alert). `provision_state=3` + preseeded data makes `fetch_pairing_data()` jump
straight to `OPEN_VERIFY_SENSOR_CERTIFICATE`, so `OPEN_SEND_PAIR` is never
reached — **Windows Hello pairing is untouched**.

`tools/fp_8054` (see §5) also reports the device already holds **9 on-device
templates** (the Windows Hello prints). Enrollment adds a template; never call
`clear_storage` or `delete` from this workspace.

## 5. Working enroll/verify tooling (no system changes)

`tools/fp_8054.c` / `tools/build.sh` build a small helper against
`build/libfprint`. It injects the preseed via the public
`fp_device_set_persistent_data()` API before every open, so fprintd and the
system libfprint are never touched:

```
tools/fp_8054 <preseed.bin> list                       # show on-device templates
tools/fp_8054 <preseed.bin> info                       # open + report features
tools/fp_8054 <preseed.bin> enroll <finger 1..10> <file>   # 10 scans -> print file
tools/fp_8054 <preseed.bin> verify <file>              # 1 touch -> match/no-match
tools/fp_8054 <preseed.bin> save <slot> <file>          # export on-device template
tools/fp_8054 <preseed.bin> delete [slot]              # remove ONLY our FP1-...-nobody
```

Reported features: storage=yes, update=no, 10 enroll stages. The device is
opened successfully with the Windows-derived key in every mode tested (`info`,
`list`, `save`, `verify`).

**Verified by user on 2026-11-20:** `list` shows 9 Windows templates; an
`enroll 2` run completed 7 stages on the sensor and committed a new template
(slot 6, `FP1-00000000-0-EBBF91FE-nobody`) but the process died with SIGSEGV
before saving the local print file. Added `save <slot> <file>` to extract a
print from device storage; `save 6` produced a 168-byte print file, and
`verify` on that file reported **`VERIFY MATCH`** after one touch. So the
full open→enroll(device)→verify loop works with Windows Hello intact.

**SIGSEGV root cause found and fixed (helper bug, not the driver).** gdb
backtrace: `enroll_data_free()` → `g_clear_object(&data->print)` →
`g_object_unref()` on a dangling pointer. `FpPrint` derives from
`G_TYPE_INITIALLY_UNOWNED`, so `fp_print_new()` returns a *floating* reference;
`fp_device_enroll()` documents `(transfer floating)` and calls
`g_object_ref_sink()` (sinks, no new ref). My helper had wrapped the template
in `g_autoptr`, so it unref'd it when `on_opened()` returned → use-after-free
(appeared around stage 7/10, where the freed memory got reused). Fix: declare
the template as a plain `FpPrint *` in `tools/fp_8054.c`; no manual unref.
Rebuilt and synced. `fp_print_deserialize()` is `(transfer full)`, so the
verify path's `g_autoptr` was already correct.

**Re-enroll after the fix (verified):** no SIGSEGV; the run progressed through
6/10 stages and then failed with `VCS_RESULT_DB_FULL`. Cause: the sensor has
exactly **10 template slots**; Windows uses 9 and the earlier crashed enroll
filled the 10th. This is a capacity limit, not a protocol/refcount bug.

Added a guarded `delete` command. It only removes prints whose description
matches our own `fpi_print_generate_user_id()` marker (`FP1-*` ... `-nobody`);
it refuses any Windows template ("Template without enrollment data"), refuses
ambiguous multi-match (use explicit slot), and confirmed with a refusal test
on slot 0. The driver additionally protects user-ID-less templates. `delete`
with no slot auto-finds our marker (slot indices were observed to shift between
runs). Executed successfully: `DELETED`, and `list` returned to exactly 9
Windows templates. A fresh enroll now has one free slot.

Note: `fp_device_set_persistent_data()` only sets an in-process property; the
caller must inject it each run (as the tool does). For permanent Ubuntu
integration see §6.

## 6. Permanent Ubuntu 26.04 integration (implemented, pending user install)

**User confirmed 2026-11-20: Windows Hello still works after all Linux
enroll/verify/delete operations. Dual boot is preserved.**

System state: Ubuntu 26.04 LTS, fprintd 1.94.5, `libfprint-2-2`
1.95.1+tod1, `libpam-fprintd` 1.94.5 installed; no PAM fingerprint rule yet.

Chosen approach — **non-destructive, no fprintd rebuild**:

- `tools/preseed_shim.c`: LD_PRELOAD shim interposing `fp_context_enumerate()`.
  It hooks `FpContext::device-added` and calls the public
  `fp_device_set_persistent_data()` on every `synatlsmoc` device with
  `/etc/fprint/8054-preseed.bin`. Verified locally: injection logged, and a
  plain `fp_device_open()` (with no manual preseed) returned `OPEN_RESULT=1`
  with no `Need to pair sensor` / `bad certificate`.
- `tools/install_ubuntu.sh` (run with sudo): installs our built libfprint +
  shim into `/opt/fprint-8054/lib`, preseed into `/etc/fprint/8054-preseed.bin`
  (0600 root), a systemd drop-in setting `LD_LIBRARY_PATH`/`LD_PRELOAD` for
  fprintd, and enables the PAM profile via `pam-auth-update`.
- `tools/uninstall_ubuntu.sh` reverts everything. **System libfprint and
  fprintd binaries are never replaced.**

Why not the upstream fprintd patch (`reference/synaTudorMiS/libfprint/
fprintd-load-store-persistent-data-from-device.patch`)? It is the canonical
route (stores blob in `/var/lib/fprint/0-persistent/synatlsmoc/0`, saves it
when the driver replaces pairing data) but requires rebuilding fprintd from
source. The shim achieves the same open-time injection through public API only.

**Safety verified:** fprintd 1.94.5 clears device storage before first enroll
only when the device has `STORAGE_CLEAR` **and not** `STORAGE_LIST`
(`src/device.c:2278-2287`). Our driver reports both (`STORAGE_LIST=yes`), so
fprintd will **not** wipe the 9 Windows templates. Also delete our custom
`FP1-...-nobody` template first (via `tools/fp_8054 ... delete`) so the 10-slot
store is not full when fprintd enrolls; the driver itself refuses to delete
templates without a user ID, protecting Windows' entries.

All 47 `fp_*` symbols fprintd 1.94.5 imports exist in our 1.94.9 fork, so the
`LD_LIBRARY_PATH` override is ABI-safe.

### 6.1 First install: root cause of the failed verify (diagnosed 2026-11-20)

`sudo bash tools/install_ubuntu.sh` ran and `fprintd-enroll` completed all 8
stages, but `fprintd-verify` returned `verify-no-match` and all later commands
reported `NoEnrolledPrints`. No `preseed-shim` lines appeared in the journal.

**Cause:** the install script copied the shim as `preseed_shim.so` while the
systemd drop-in sets `LD_PRELOAD=/opt/fprint-8054/lib/libpreseed_shim.so`.
The loader silently ignored the missing preload, so fprintd opened the sensor
with **no pairing data and sent a fresh PAIR on every open**. `LD_LIBRARY_PATH`
still worked (the device name "Synaptics Tudor Match-In-Sensor" is our fork's),
so our driver — not the system TOD lib — was in use.

**Why the print disappeared:** fprintd 1.94.5 `check_local_storage()`
(`src/device.c:1330-1410`) runs after a failed verify. It calls
`fp_device_list_prints_sync()` and deletes any host print file whose `FpPrint`
is not `fp_print_equal()` to an on-device print. With a new PAIR each open the
saved print no longer matched an on-device template, so fprintd deleted its own
print file. This is fprintd cleanup, **not** a Windows template deletion.

**Fix applied:** `install_ubuntu.sh` now installs the shim as
`libpreseed_shim.so` and fails fast if the drop-in and file paths disagree.

**Windows pairing is still intact:** after the incident,
`tools/fp_8054 Windows/8054-preseed.bin list` opened the sensor successfully
with the original preseed, no PAIR and no bad-certificate error.

### 6.2 On-device state after the failed verify

`list` shows 10/10 slots: 8x "Template without enrollment data" (Windows
templates — the driver refuses to delete user-ID-less prints at
`synatlsmoc.c:4373-4382`) and 2 Linux-owned templates with a user-ID payload
at slots 2 and 5. fprintd deleted only its host-side print file; the on-device
template remains. Added `tools/fp_8054 ... delete-linux [slot]` which deletes
only templates that carry a user ID and refuses Windows templates; refusal was
verified on slot 0 and the ambiguous no-slot case correctly reported slots 2
and 5 without deleting anything.

## 7. Verified working (2026-11-20)

After re-running the corrected installer, deleting the two stale Linux
templates (`delete-linux 5`, then `delete-linux 2`), the device listed exactly
8 Windows templates. Then:

- `fprintd-enroll -f left-index-finger <user>` → all 8 stages passed,
  `enroll-completed`.
- `fprintd-verify -f left-index-finger <user>` → **`verify-match (done)`**.
- `fprintd-list <user>` → `left-index-finger` listed under
  "Synaptics Tudor Match-In-Sensor (press)".
- `sudo journalctl -u fprintd -b --no-pager | grep -i preseed-shim` →
  `hooked FpContext::device-added` and `injected 1082 bytes ... into
  synatlsmoc device 0` on both fprintd starts.

Dual-boot note: the sensor originally held 9 Windows templates; it now holds
8. The earlier no-preseed fprintd attempts appear to have replaced one
Windows slot. Windows Hello should still work with the remaining 8, but this
must be re-confirmed in Windows; if a finger is missing, re-enroll it there.

Remaining validation: restart fprintd and re-verify (proves persistence across
daemon restarts), test PAM via `sudo -k && sudo true` and the lock screen,
then re-check Windows Hello after a dual-boot cycle.

No PRs, pushes, or changes to the cloned upstream repos will be made from this
workspace. Hardware claims are marked `verified` only after a real test.
