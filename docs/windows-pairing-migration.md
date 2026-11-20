# Preserving Windows Hello while enabling `synatlsmoc` on Kensington VeriMark IT `047d:8054`

Research-only runbook. It does **not** modify `reference/`.

**Live update (2026-11-19):** a read-only GET_VERSION probe on the target `8054`
confirmed firmware **10.1**, `security=0x0b` (advanced security set),
`iface=0xa1` (keyflag bit 0x20 set → use `pubkey_v10_1_kf`), and
`provision_state=3` (PROVISIONED). Offline validation of the cloned sample cert
succeeded against `pubkey_v10_1_kf`, and the preseed→open path was exercised with
sample data: libfprint **skipped PAIR** and reached TLS, failing only with the
expected `bad certificate` alert because the sample key is not this sensor's.
The converter in §5 had a struct-format bug (`x` pad is valueless in Python
`struct`); the corrected format `<HH68s68sBBH256s` is used in
`tools/pairing/make_preseed.py`, which is the reference implementation. No
fingerprint/pairing state was modified on the device.

**Evidence labels:** `[S]` source-verified in a cloned repo; `[O]` offline check from cloned
sample data; `[I]` inference from cited sources; `[U]` unverified on `047d:8054` hardware.

## Source keys (all paths relative to workspace root)

- `[P]` `reference/synaTudorMiS/libfprint/fprintd-load-store-persistent-data-from-device.patch`
- `[D]` `reference/libfprint-vojtapl/libfprint/fp-device.c`
- `[S]` `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/synatlsmoc.c`
- `[H]` `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/pairing.h`
- `[C]` `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/pairing.c`
- `[K]` `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/sensor_public_keys.h`
- `[T]` `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/tagval.c`
- `[42]` `reference/verimark-linux-driver/findings/42-owner-key-extraction-DPAPI.md`
- `[E]` `reference/verimark-linux-driver/tools/extract-pairing-key.py`
- `[OWN]` `reference/verimark-linux-driver/prototype/build_owner_pdata.py`
- `[43]` `reference/verimark-linux-driver/findings/43-owner-key-impersonation-NEGATIVE.md`
- `[49]` `reference/verimark-linux-driver/findings/49-truncated-command-was-the-blocker-BREAKTHROUGH.md`
- `[51]` `reference/verimark-linux-driver/findings/51-moc-enroll-verify-WORKING.md`
- `[RV]` `reference/synaTudorMiS/rev/FINDINGS.md`
- `[SP]` `reference/synaTudorMiS/reverse engineering/SP141455/notes`
- `[RM]` `reference/synaTudorMiS/README.md`
- `[DI]` `reference/synaTudorMiS/libfprint/DRIVER_ISSUES.md`
- `[AG]` `reference/synaTudorMiS/AGENTS.md`
- `[X]` `FINDINGS.md`
- `[VM]` `reference/verimark-linux-driver/driver/verimark.c`

## 1. Goal and hard constraints

- `047d:8054` is served by Windows build `synaWudfBioUsb123.dll` v6.0.25.1123 (`synaWudfBioUsbUwpOne.inf`); the libfprint fork already lists VID `047d`, PID `8054` in `synatlsmoc`'s `id_table`. [AG:80; S:128-129; X:23-27] `[S]`
- The sensor holds one host pairing: a fresh PAIR replaces the old one, and Windows re-pairs when its pairing is rejected, invalidating Linux's stored copy (`PAIR-1`). Therefore **never let Linux run `0x93 PAIR` first** if Windows Hello must keep working. [DI:19-28] `[S]`
- Enrollments are tied to the pairing data (template id, finger id, Windows SID), so replacing pairing can break Hello templates even if a new Linux pairing "works". [RM:84-85] `[S]`
- Windows can also read pairing data from the sensor's host partition, but it is DPAPI-wrapped and not reusable outside that Windows install; the registry copy is the practical extraction source. [RV:779-803] `[S]`
- This doc addresses **pairing continuity**, not the old `0x0405` "ownership gate": that gate was a 2-byte command bug on `00f2`, and full Linux MOC enroll/verify was later demonstrated there. Do not generalize that result to `8054`, whose transport and driver build differ. [49:1-9,49-55; 51:1-27; X:29-32] `[S]`

## 2. fprintd on-disk format

- The patched fprintd loads persistent data during device construction and saves on dispose or when the driver replaces `fpi-persistent-data`. [P:15-16,45-56] `[S]`
- Storage path: `get_storage_path()/0-persistent/<driver>/<device_id>`; directories `0700`, file mode `0600`, atomic write. [P:68-70,91-92,110-129,139-145] `[S]`
- `fp_device_get_persistent_data()` serializes a GVariant `(issv)`: version `1`, driver string, device id, then the driver's variant. `fp_device_set_persistent_data()` parses `(i&s&sv)` and rejects version != 1 or driver/device-id mismatch. [D:802-812,869-899] `[S]`
- Driver id is `synatlsmoc` (`FP_COMPONENT` becomes `dev_class->id`). Default `device_id` is `"0"`. [S:27,4738; D:177] `[S]`
- Therefore the expected preseed file is:

  ```text
  /var/lib/fprint/0-persistent/synatlsmoc/0
  ```

  `[I]` The `0` component follows from the default `device_id`; the fork's `synatlsmoc.c` does not publish a custom id. Confirm from fprintd debug output before relying on it. `get_storage_path()` may also be overridden in a custom build. [D:177; P:68,139] `[I]`

- `synatlsmoc` driver payload is `(@ay@ay@s)` = `(client_cert_raw[400], server_cert_raw[400], privkey_pem)`. On disk its type string is `(ayays)`; `@` only changes GVariant construction, not the serialized type. [S:3584-3594,3638-3648] `[S]`
- Certificate constants: 400-byte certificate, 142-byte signed prefix, `sign_size` u16 after it, up to 256-byte signature, magic `0x5f3f`, curve `23`. [H:33-42; S:316-342] `[S]`
- The PEM key is decoded as any EC PEM by OpenSSL's decoder; the driver writes PKCS#8-style PEM via `PEM_write_bio_PrivateKey()`. [S:3535,3700-3714] `[S]`
- If provisioned and persistent data exists, `fetch_pairing_data()` loads it and jumps directly to `OPEN_VERIFY_SENSOR_CERTIFICATE`, skipping `OPEN_SEND_PAIR`. A PAIR sets `pairing_needs_save = TRUE`; preseeded data keeps it false, so fprintd will not overwrite the file. [S:3767-3794,3910-3923] `[S]`

## 3. Windows DPAPI capture and TagVal mapping

### 3.1 Registry and DPAPI

- The registry key is `HKU\S-1-5-19\Software\Synaptics\PairingData` ( equivalently LOCAL SERVICE's `HKCU\Software\Synaptics\PairingData`). For `00f2` the value name was the sensor id `F7007AD929C60000`. [42:15-18; RV:783-785] `[S]`
- `[U]` For `8054` the value name is **not documented**. Enumerate the key on Windows and pick the value whose name matches the device's sensor id; do not reuse the `00f2` constant. The extraction script hardcodes the `00f2` id in two places and must be copied before editing. [E:29-31,48-51] `[I]`
- The sibling driver reads the 6-byte sensor id from GET_VERSION reply bytes `[18:24]`; the `00f2` registry name is those 6 bytes plus `0000` (`f7007ad929c6` + `0000`). `[I]` Apply that rule only after confirming with a real `8054` GET_VERSION and an actual registry enumeration. [VM:247-254; 42:16] `[I]`
- Export with `reg query` / `reg export` (read-only; do **not** run the unpair script, which deletes state). The existing extraction script expects a backup `.reg` path but its PowerShell decrypt prefers the live registry value. [E:38-58,118-120; 42:17-18] `[S]`
- Stored value layout: 16-byte Synaptics wrapper (`01000000 00000000 e6050000 06010000`), then a DPAPI blob starting `01000000 d08c9ddf...`; strip exactly 16 bytes. Decrypted plaintext is a TagVal container. [42:20-27,39-48] `[S]`
- DPAPI parameters verified from `synaWudfBioUsb132.dll`: `CryptUnprotectData`, `pOptionalEntropy = NULL`, `dwFlags = 0`, user-scoped under `S-1-5-19`. Decrypt as `LOCAL SERVICE` (the script stages a one-shot scheduled task as `LOCAL SERVICE`). [42:28-37; E:138-142] `[U]` Same scheme for v123 is an inference, not a hardware-verified fact.
- `tools/extract-pairing-key.bat` self-elevates and emits `pairing-fields.json` with `{tag,len,hex}` entries. [E:15-19,171-179] `[S]`

### 3.2 TLV endianness and tag map

- `[S]` TagVal framing is `[tag u16 LE][length u32 LE][data]`, both in libfprint's parser/serializer and in the extraction script, which notes verification against a real blob. [T:79-81,122-124; E:94-104] The older "big-endian" note in `findings/42` is superseded. [42:40-43] `[S]`
- Tag numbering: `0` version, `1` host cert, `2` private key, `3` sensor cert, `4` public-key security data, `5` PSK id. The SP141455 notes independently list the same tags and lengths (host/sensor cert `0x190`, private key `0x20`). [H:180-188; SP:1003-1009] `[S]`
- Real extracted data used a 32-byte little-endian tag-2 scalar; older notes called it "~68 B / 0x44", and `rev`'s `.pdata` stores the scalar in a 68-byte LE field. Accept either representation by taking the low 32 bytes LE. [OWN:52-56; `reference/verimark-linux-driver/prototype/p2_moc.py:386-392`; 42:44-48; `reference/synaTudorMiS/pydrv/tudor/sensor/pair.py:98-103,128-132`] `[S]`
- Identification rule: exactly one 400-byte blob verifies as the sensor certificate against the sensor's built-in public key; that blob is the sensor cert, the other is the host cert. Then the tag-2 scalar must derive to the host cert's public key. [OWN:60-91; 43:12-19] `[O/S]`
- Use the Windows tag-1 bytes as `client_cert_raw` verbatim. The fork's `create_host_certificate()` makes a fresh cert/key and PAIR overwrites stored certs, so calling it would defeat the migration. [C:104-228; S:3750-3764,1619-1622] `[S]`

## 4. Offline certificate validation

- A cert is parsed as: u16 LE magic, u16 LE curve, 68-byte x field (low 32 bytes significant), 68-byte y field, 1 pad, u8 `cert_type`, u16 LE `sign_size`, 256-byte signature. x/y are reversed to big-endian before building an OpenSSL P-256 key. [S:306-366; H:44-54; `reference/synaTudorMiS/pydrv/tudor/sensor/pair.py:44-61`] `[S]`
- The signature is ECDSA-SHA256 over the first `CERTIFICATE_DATA_SIZE` (142) bytes, using `sign_size` bytes at offset 144. [H:33-42; S:274-304] `[S]`
- Sensor public keys are hardcoded by firmware major/minor and a `keyflag`; for FW 10.1 the two points are `pubkey_v10_1` and `pubkey_v10_1_kf`, selected by `synatlsmoc_key_flag()`. [K:32-86; S:207-260] `[S]`
- `[O]` Offline check against cloned sample data: `sample_sensor_cert` verifies with the 10.1-kf point; `sample_recv_host_cert` does not, matching the tag-3/tag-1 identification rule above. [43:12-19; `reference/libfprint-vojtapl/libfprint/drivers/synatlsmoc/sample_pairing_data.h:58-97`; K:68-86] `[O]`
- `[U]` `8054`'s firmware version and `keyflag` have not been read here; select the point from GET_VERSION before trusting the sensor-cert check. [X:61-64; K:32-86] `[I]`

## 5. Python preseed recipe

Run on Linux with Python 3 + `python3-gi` + `python-cryptography`. It **only writes a file**; no USB or PAIR is sent. Requires `pairing-fields.json` from Windows. Path/permissions are from section 2.

```python
#!/usr/bin/env python3
import json, os, struct, sys, tempfile
from pathlib import Path
from gi.repository import GLib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# FW 10.1 + keyflag point from sensor_public_keys.h; change for 8054 if GET_VERSION differs.
SENSOR_PUB = bytes.fromhex(
    "04cb656293b9701806ae3b1a5208e469f465a6a5195bd8b7e39f23650611dcdfdc"
    "a700424ee097b3c159be791089502f40ba571eca91b106b4881f19637e44bfdc")
sensor_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), SENSOR_PUB)

def cert_info(raw):
    assert len(raw) == 400
    magic, curve, x, y, pad, ctype, slen, sig = struct.unpack("<HH68s68sBBH256s", raw)
    assert (magic, curve) == (0x5f3f, 23) and 0 < slen <= 256
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x[:32][::-1], "big"), int.from_bytes(y[:32][::-1], "big"),
        ec.SECP256R1())
    return nums.public_key(), raw[:142], sig[:slen], ctype

def sensor_ok(raw):
    pub, signed, sig, _ = cert_info(raw)
    try:
        sensor_pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def load_key(blob):
    if blob.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(blob, None)
    scalar = blob[:32]                    # 32-B LE scalar or low 32 B of 68-B LE field
    return ec.derive_private_key(int.from_bytes(scalar, "little"), ec.SECP256R1())

src = Path(sys.argv[1] if len(sys.argv) > 1 else "pairing-fields.json")
out = Path(sys.argv[2] if len(sys.argv) > 2 else
           "/var/lib/fprint/0-persistent/synatlsmoc/0")
ents = {int(e["tag"]): bytes.fromhex(e["hex"])
        for e in json.loads(src.read_text())["entries"]}
c1, c3 = ents[1], ents[3]
if sensor_ok(c1) == sensor_ok(c3):         # exactly one must verify
    sys.exit("cert identification ambiguous")
sensor_cert, host_cert = (c1, c3) if sensor_ok(c1) else (c3, c1)
key = load_key(ents[2])
want = key.public_key().public_numbers()
have = cert_info(host_cert)[0].public_numbers()
if (want.x, want.y) != (have.x, have.y):
    sys.exit("tag-2 private key does not match the host cert")

pem = key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode("ascii")
inner = GLib.Variant.new_tuple(GLib.Variant("ay", host_cert),
                               GLib.Variant("ay", sensor_cert),
                               GLib.Variant("s", pem))
assert inner.get_type_string() == "(ayays)"     # == C's "(@ay@ay@s)" on disk
outer = GLib.Variant("(issv)", (1, "synatlsmoc", "0", inner))
blob = bytes(outer.get_data_as_bytes().get_data())
assert len(blob) == outer.get_size()

out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".pairing-")
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    os.replace(tmp, out)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
print(f"wrote {len(blob)} bytes to {out}")
```

The `get_data_as_bytes()` result is the serialized form that libfprint reparses with
`g_variant_new_from_data()` / `g_variant_get()`. [D:869-879] `[S]`

## 6. Runbooks (verified path on this machine, 2026-11-20)

### Windows (read-only; keep Hello intact)

1. The pairing blob is **not** under `HKU\S-1-5-19\Software\Synaptics\PairingData`
   on this installation. It is a device-specific value:
   `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_047D&PID_8054\<serial>\Device
   Parameters\synaWudfBioUsb123` → value `<MIS serial in uppercase>` (here
   `<MIS_SERIAL_HEX>`), 1788 bytes. `[V]`
2. Export the containing key with `reg export` (read-only). The original
   `extract-pairing-8054.ps1` crashed on a bad `icacls` SID before searching;
   `extract-8054-minimal.ps1` targets this exact value and works. `[V]`
3. Do **not** run unpair/reset/clear-storage scripts. No Windows Hello data is
   modified by reading this value. `[V]`

### Linux (offline decryption + no sensor writes)

1. Mount the Windows partition read-only:
   `sudo mount -o ro /dev/nvmeXn1pY /run/media/$USER/Win11Pro`. `[V]`
2. Extract the DPAPI portion (strip the 16-byte Synaptics wrapper) to
   `/tmp/opencode/8054-dpapi.bin`, then run:
   `python3 tools/pairing/offline_decrypt.py`. It reads the SYSTEM/SECURITY
   hives and `System32\Microsoft\Protect\S-1-5-18\User\71359010-...`, derives
   the DPAPI_SYSTEM keys, decrypts the master key and the blob, and writes
   `Windows/plain.bin` + `Windows/pairing-fields.json`. `[V]`
3. Build the preseed:
   `python3 tools/pairing/make_preseed.py Windows/plain.bin Windows/8054-preseed.bin`
   (mode 600). It verifies the sensor cert against `pubkey_v10_1_kf` and checks
   the private key matches the host cert. `[V]`
4. Validate with `LD_LIBRARY_PATH=build/libfprint ./tools/pairing/test_open
   Windows/8054-preseed.bin`. Success = `Open completed successfully`, no
   `Need to pair sensor`, no TLS `bad certificate`. `[V]`
5. Use `tools/fp_8054` for `list`/`enroll`/`verify` (see `FINDINGS.md` §5).
   `fp_device_set_persistent_data()` is in-process only, so the preseed is
   injected on every run. Permanent fprintd integration is provided by
   `tools/preseed_shim.c` + `tools/install_ubuntu.sh` (see `FINDINGS.md` §6–7),
   which injects the same blob into fprintd without patching it. `[V]`
6. Reboot into Windows and confirm Hello still verifies. `[I]` (user action)

## 7. Caveats / unresolved

- `[V]` DPAPI scheme, registry value name, sensor id, firmware/keyflag and the
  TLS handshake are now **verified on this `8054` PID** by offline decryption
  plus a successful open with Windows' key. Windows Hello itself still needs a
  user-side re-check after Linux enrollment. `[I]`
- `[U]` Windows Hello template compatibility after Linux enrollment: the
  device already holds 9 templates and enrollment appears to add one, but a
  real enroll+Windows re-check by the user is still pending. `[I]`
- `pydrv` is a lab tool and not protocol evidence; it is cited above only for
  byte layouts already mirrored in the C driver. `[S]`
- The old owner-key experiments proved the sensor verifies the client
  CertificateVerify (wrong key => TLS alert 47), which supports reusing the
  exact Windows key rather than regenerating one. [43:31-41] `[S]`
- If you must PAIR from Linux, Windows Hello should be considered invalidated;
  re-extract and re-preseed, or accept a fresh Windows setup. [DI:19-28; RM:84-85] `[S]`

Legend: `[V]` verified on this machine, `[S]` source-cited, `[I]` inference,
`[U]` unresolved.
