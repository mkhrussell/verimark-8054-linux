#!/usr/bin/env python3
"""
Convert Windows pairing-fields.json into libfprint's persistent-data file
for the synatlsmoc driver. No USB writes; only writes a local file.

Usage:
  python3 make_preseed.py <pairing-fields.json | plain.bin> [output-file]

Default output: /var/lib/fprint/0-persistent/synatlsmoc/0
Requires: python3-gi (GLib), python3-cryptography.
"""
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

from gi.repository import GLib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Sensor public keys from sensor_public_keys.h, FW 10.1. Our 047d:8054 probe
# reported iface=0xa1 -> KEY_FLAG_MASK(0x20) set -> keyflag TRUE -> use _kf.
# Both are listed so identification is evidence-based, not assumed.
SENSOR_PUBS = {
    "v10_1": bytes.fromhex(
        "04" "33d6208ca5f5da824b46ea1ca25e67327efc0c4ce937d9d844120d6cc08bfe5d"
             "b955e181fc4bf6c62b91afcdf3b61ec718dce7084742c41f57c1f0777c34a0fd"),
    "v10_1_kf": bytes.fromhex(
        "04" "cb656293b9701806ae3b1a5208e469f465a6a5195bd8b7e39f23650611dcdfdc"
             "a700424ee097b3c159be791089502f40ba571eca91b106b4881f19637e44bfdc"),
}
SENSOR_KEYS = {
    n: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p)
    for n, p in SENSOR_PUBS.items()
}


def cert_info(raw):
    assert len(raw) == 400, len(raw)
    magic, curve, x, y, pad, ctype, slen, sig = struct.unpack("<HH68s68sBBH256s", raw)
    if magic != 0x5F3F or curve != 23 or not (0 < slen <= 256):
        raise ValueError(f"bad cert header magic={magic:#x} curve={curve} slen={slen}")
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x[:32][::-1], "big"),
        int.from_bytes(y[:32][::-1], "big"),
        ec.SECP256R1(),
    )
    return nums.public_key(), raw[:142], sig[:slen], ctype, slen


def sensor_ok(raw, pub):
    try:
        _, signed, sig, _, _ = cert_info(raw)
        pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def load_priv(blob):
    if blob.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(blob, None)
    # 32-byte LE scalar, or low 32 bytes of a 68-byte LE field.
    scalar = blob[:32]
    return ec.derive_private_key(int.from_bytes(scalar, "little"), ec.SECP256R1())


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "pairing-fields.json")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else
               "/var/lib/fprint/0-persistent/synatlsmoc/0")
    raw = src.read_bytes()
    if raw[:1] == b"{":  # pairing-fields.json
        data = json.loads(raw.decode("utf-8"))
        ents = {int(e["tag"]): bytes.fromhex(e["hex"]) for e in data["entries"]}
    else:  # raw decrypted TagVal (plain.bin)
        ents, i = {}, 0
        while i + 6 <= len(raw):
            tag = int.from_bytes(raw[i:i + 2], "little")
            ln = int.from_bytes(raw[i + 2:i + 6], "little")
            if ln > len(raw) - i - 6:
                break
            ents[tag] = raw[i + 6:i + 6 + ln]
            i += 6 + ln
        data = {"sensor_id": os.environ.get("MIS_SERIAL", "<MIS_SERIAL_HEX>"), "dpapi_user": "LOCAL SERVICE"}
        print(f"parsed TagVal: {len(ents)} entries from {len(raw)} bytes")
    print(f"source: {src}  sensor_id={data.get('sensor_id')}  "
          f"dpapi_user={data.get('dpapi_user')}  entries={sorted(ents)}")

    c1, c2, c3 = ents.get(1), ents.get(2), ents.get(3)
    if not c1 or not c2 or not c3:
        sys.exit("need TagVal tags 1 (host cert), 2 (private key), 3 (sensor cert)")

    certs = [c for c in (c1, c3) if len(c) == 400]
    if len(certs) != 2:
        sys.exit(f"expected two 400-byte certs, got lengths {len(c1)}, {len(c3)}")

    # Identify the sensor cert: exactly one verifies against a 10.1 key.
    matches = []
    for kname, pub in SENSOR_KEYS.items():
        for label, blob in (("tag1", c1), ("tag3", c3)):
            if sensor_ok(blob, pub):
                matches.append((kname, label, blob))
    if not matches:
        sys.exit("neither cert verifies against any FW 10.1 sensor public key; "
                 "firmware key/format may differ - do NOT proceed")
    kname, sensor_label, sensor_cert = matches[0]
    host_cert = c3 if sensor_label == "tag1" else c1
    host_label = "tag1" if host_cert is c1 else "tag3"
    print(f"sensor cert = {sensor_label} (verified with {kname}); "
          f"host cert = {host_label}")

    key = load_priv(c2)
    want = key.public_key().public_numbers()
    have = cert_info(host_cert)[0].public_numbers()
    if (want.x, want.y) != (have.x, have.y):
        sys.exit("private key does not match host certificate public key")

    for label, blob in (("host", host_cert), ("sensor", sensor_cert)):
        _, _, _, ctype, slen = cert_info(blob)
        print(f"  {label} cert: cert_type={ctype} sign_size={slen}")

    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    inner = GLib.Variant.new_tuple(
        GLib.Variant("ay", host_cert),
        GLib.Variant("ay", sensor_cert),
        GLib.Variant("s", pem),
    )
    assert inner.get_type_string() == "(ayays)", inner.get_type_string()
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
    print(f"verify with: stat -c '%a %U %n' {out}")


if __name__ == "__main__":
    main()
