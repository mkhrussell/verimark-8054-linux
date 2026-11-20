#!/usr/bin/env python3
"""
Offline DPAPI decryption of the Kensington 047d:8054 Synaptics pairing blob,
using the mounted Windows partition's hives. No Windows boot required.

Inputs (paths relative to WINROOT):
  SYSTEM / SECURITY hives      -> DPAPI_SYSTEM MachineKey/UserKey
  System32/Microsoft/Protect/S-1-5-18/User/71359010-...  -> master key
  047d:8054 pairing blob exported from the registry (dpapi.bin)

Outputs:
  Windows/plain.bin  (decrypted TagVal container) and Windows/pairing-fields.json

Notes:
  Implements the small subset of impacket's secretsdump.LocalOperations /
  LSASecrets that we need, so we avoid importing secretsdump (which drags in
  LDAP -> pyOpenSSL). Only impacket.winregistry + impacket.dpapi are used.
"""
import hashlib
import json
import os
import sys
from binascii import hexlify, unhexlify
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "reference" / "impacket"))

from Cryptodome.Cipher import AES  # noqa: E402
from impacket.structure import Structure  # noqa: E402
from impacket import winregistry  # noqa: E402
from impacket.dpapi import (  # noqa: E402
    DPAPI_SYSTEM, MasterKeyFile, MasterKey, DPAPI_BLOB,
)

# Minimal LSA structures from secretsdump.py (vista+ style).
class LSA_SECRET_BLOB(Structure):
    structure = (
        ("Length", "<L=0"),
        ("Unknown", "12s=b\"\""),
        ("_Secret", "_-Secret", "self[\"Length\"]"),
        ("Secret", ":"),
        ("Remaining", ":"),
    )


class LSA_SECRET(Structure):
    structure = (
        ("Version", "<L=0"),
        ("EncKeyID", "16s=b\"\""),
        ("EncAlgorithm", "<L=0"),
        ("Flags", "<L=0"),
        ("EncryptedData", ":"),
    )


def sha256_1000(key, value):
    sha = hashlib.sha256()
    sha.update(key)
    for _ in range(1000):
        sha.update(value)
    return sha.digest()


def decrypt_aes(key, value, iv=b"\x00" * 16):
    """secretsdump.CryptoCommon.decryptAES (CBC, resets IV per block when zero)."""
    plain = b""
    aes = None
    for index in range(0, len(value), 16):
        chunk = value[index:index + 16]
        if len(chunk) < 16:
            chunk += b"\x00" * (16 - len(chunk))
        if iv == b"\x00" * 16 or aes is None:
            aes = AES.new(key, AES.MODE_CBC, iv)
        plain += aes.decrypt(chunk)
    return plain


def get_boot_key(system_hive):
    reg = winregistry.get_registry_parser(str(system_hive), False)
    current = reg.getValue("\\Select\\Current")[1]
    ccs = "ControlSet%03d" % current
    tmp = b""
    for key in ("JD", "Skew1", "GBG", "Data"):
        cls = reg.getClass("\\%s\\Control\\Lsa\\%s" % (ccs, key))
        tmp += cls[:16].decode("utf-16le").encode()
    raw = unhexlify(tmp)
    transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    boot_key = b"".join(raw[t:t + 1] for t in transforms)
    print(f"[*] boot key: {hexlify(boot_key).decode()}")
    return boot_key


def get_lsa_key(security_hive, boot_key):
    reg = winregistry.get_registry_parser(str(security_hive), False)
    value = reg.getValue("\\Policy\\PolEKList\\default")
    if value is None:
        sys.exit("[X] PolEKList not found (unexpected on Win11)")
    record = LSA_SECRET(value[1])
    tmp_key = sha256_1000(boot_key, record["EncryptedData"][:32])
    plain = decrypt_aes(tmp_key, record["EncryptedData"][32:])
    blob = LSA_SECRET_BLOB(plain)
    lsa_key = blob["Secret"][52:][:32]
    print(f"[+] LSA key: {hexlify(lsa_key).decode()}")
    return lsa_key


def get_dpapi_system(security_hive, lsa_key):
    reg = winregistry.get_registry_parser(str(security_hive), False)
    parent = reg.findKey("\\Policy\\Secrets")
    keys = reg.enumKey(parent) if parent is not None else None
    if not keys:
        sys.exit("[X] no LSA secrets found")
    keys = [k for k in keys if k not in (b"NL$Control", "NL$Control")]
    found = {}
    for key in keys:
        name = key.decode() if isinstance(key, bytes) else key
        value = reg.getValue("\\Policy\\Secrets\\{}\\CurrVal\\default".format(name))
        if value is None or not value[1]:
            continue
        record = LSA_SECRET(value[1])
        tmp_key = sha256_1000(lsa_key, record["EncryptedData"][:32])
        plain = decrypt_aes(tmp_key, record["EncryptedData"][32:])
        blob = LSA_SECRET_BLOB(plain)
        secret = blob["Secret"]
        if name.upper().startswith("DPAPI_SYSTEM"):
            dpapi = DPAPI_SYSTEM(secret)
            found["MachineKey"] = dpapi["MachineKey"]
            found["UserKey"] = dpapi["UserKey"]
            print(f"[+] found DPAPI_SYSTEM secret ({len(secret)} bytes)")
            break
    if not found:
        sys.exit("[X] DPAPI_SYSTEM secret not found in SECURITY hive")
    return found


def decrypt_master_key(mk_data, keys):
    mkf = MasterKeyFile(mk_data)
    print(f"[*] master key file: version={mkf['Version']} "
          f"masterkeylen={mkf['MasterKeyLen']} backupkeylen={mkf['BackupKeyLen']}")
    off = len(mkf)
    mk = MasterKey(mk_data[off:off + mkf["MasterKeyLen"]]) if mkf["MasterKeyLen"] else None
    off2 = off + (mkf["MasterKeyLen"] or 0)
    bkmk = MasterKey(mk_data[off2:off2 + mkf["BackupKeyLen"]]) if mkf["BackupKeyLen"] else None

    for name, k in (("MachineKey", keys["MachineKey"]), ("UserKey", keys["UserKey"])):
        for label, obj in (("master", mk), ("backup", bkmk)):
            if obj is None:
                continue
            try:
                dec = obj.decrypt(k)
            except Exception as e:
                print(f"    {label}/{name}: decrypt raised {e}")
                continue
            if dec:
                print(f"[+] decrypted {label} key with {name}: {hexlify(dec).decode()}")
                return dec
    sys.exit("[X] could not decrypt master key with either DPAPI_SYSTEM key")


def main():
    winroot = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("WINROOT", "/mnt/windows"))
    blob_path = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/8054-dpapi.bin")
    mk_dir = (winroot / "Windows" / "System32" / "Microsoft" / "Protect" /
              "S-1-5-18" / "User")
    mk_guid = os.environ.get("DPAPI_MK_GUID")
    if mk_guid:
        mk_paths = [mk_dir / mk_guid]
    else:
        # No hardcoded GUID: try every master key in the LOCAL SERVICE store.
        mk_paths = sorted(p for p in mk_dir.iterdir() if p.is_file())
        if not mk_paths:
            sys.exit(f"[X] no master key files in {mk_dir}")
        print(f"[*] trying {len(mk_paths)} master key candidate(s) in {mk_dir}")
    system_hive = winroot / "Windows" / "System32" / "config" / "SYSTEM"
    security_hive = winroot / "Windows" / "System32" / "config" / "SECURITY"
    out_dir = REPO / "Windows"

    for p in (system_hive, security_hive, blob_path):
        if not p.exists():
            sys.exit(f"[X] missing input: {p}")

    boot_key = get_boot_key(system_hive)
    lsa_key = get_lsa_key(security_hive, boot_key)
    keys = get_dpapi_system(security_hive, lsa_key)

    blob = DPAPI_BLOB(blob_path.read_bytes())
    print(f"[*] DPAPI blob: flags={blob['Flags']} "
          f"masterkey_guid={hexlify(blob['GuidMasterKey']).decode()}")

    master = None
    for mk_path in mk_paths:
        if not mk_path.exists():
            sys.exit(f"[X] missing input: {mk_path}")
        try:
            candidate = decrypt_master_key(mk_path.read_bytes(), keys)
        except Exception as exc:
            print(f"[-] {mk_path.name}: {exc}")
            continue
        if candidate:
            master = candidate
            print(f"[+] master key decrypted from {mk_path.name}")
            break
    if not master:
        sys.exit("[X] could not decrypt any master key")

    plain = blob.decrypt(master)
    if not plain:
        sys.exit("[X] DPAPI_BLOB.decrypt failed")

    out_dir.mkdir(parents=True, exist_ok=True)
    plain_path = out_dir / "plain.bin"
    plain_path.write_bytes(plain)
    print(f"[+] wrote {len(plain)} bytes to {plain_path}")

    entries, i = [], 0
    while i + 6 <= len(plain):
        tag = int.from_bytes(plain[i:i + 2], "little")
        ln = int.from_bytes(plain[i + 2:i + 6], "little")
        if ln > len(plain) - i - 6:
            break
        entries.append({"tag": tag, "len": ln,
                        "hex": hexlify(plain[i + 6:i + 6 + ln]).decode()})
        i += 6 + ln
    fields = {"sensor_id": os.environ.get("MIS_SERIAL", "<MIS_SERIAL_HEX>"), "dpapi_user": "offline-hive",
              "plain_len": len(plain), "entries": entries}
    json_path = out_dir / "pairing-fields.json"
    json_path.write_text(json.dumps(fields, indent=2))
    print(f"[+] wrote {len(entries)} TagVal entries to {json_path}")
    for e in entries:
        note = " <- 400-B cert" if e["len"] == 400 else (
            " <- EC private key?" if 60 <= e["len"] <= 80 else "")
        print(f"    tag=0x{e['tag']:04x} len={e['len']:<4}{note}")


if __name__ == "__main__":
    main()
