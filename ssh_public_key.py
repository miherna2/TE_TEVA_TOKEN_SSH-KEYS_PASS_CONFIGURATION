"""Parse and validate one SSH public key without loading SSH/Netmiko dependencies."""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

from common import StepError, read_text


KEY_TYPES = {"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521"}
MAX_BLOB = 16 * 1024  # an RSA-16384 public key is about 2 KiB


@dataclass(frozen=True)
class PublicKey:
    text: str = field(repr=False)
    key_type: str
    base64_data: str = field(repr=False)
    fingerprint_sha256: str
    fingerprint_md5: str


def load_public_key(path: Path) -> PublicKey:
    if not path.is_file():
        raise StepError(f"public-key file not found: {path}")
    content = read_text(path)
    if "PRIVATE KEY" in content:
        raise StepError(f"{path.name} is a PRIVATE key; point TE_SSH_PUBLIC_KEY_PATHS at the "
                        "matching .pub file (never upload a private key)")
    if "BEGIN SSH2 PUBLIC KEY" in content or "PuTTY-User-Key-File" in content:
        raise StepError(f"{path.name} is in PuTTY format; in PuTTYgen, copy the box 'Public key for "
                        "pasting into OpenSSH authorized_keys file' into a .pub file and use that")
    lines = [line.strip() for line in content.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise StepError(f"{path.name} must contain exactly one SSH public key line")
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise StepError(f"{path.name} is not a supported OpenSSH public key (expected a line "
                        "starting with ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256/384/521)")
    key_type, data = parts[0], parts[1]
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StepError(f"{path.name}: the key data is not valid base64; regenerate or recopy "
                        "the key") from exc
    # The key data starts with its own type name; it must agree with the label in front of it.
    embedded = raw[4:4 + struct.unpack(">I", raw[:4])[0]] if len(raw) >= 4 else b""
    if not raw or len(raw) > MAX_BLOB or embedded != key_type.encode() or (
            key_type == "ssh-ed25519" and len(raw) != 51):
        raise StepError(f"{path.name} is not a valid {key_type} key (the type label and key data do "
                        "not match, or the key is truncated); regenerate it with ssh-keygen")
    comment = " ".join(parts[2:])
    if not comment.isascii() or not comment.isprintable():
        comment = ""  # Only plain ASCII text reaches the appliance's authorized_keys.
    sha256 = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    md5 = ":".join(f"{byte:02x}" for byte in hashlib.md5(raw, usedforsecurity=False).digest())
    text = f"{key_type} {data}" + (f" {comment}" if comment else "")
    return PublicKey(text, key_type, data, sha256, md5)
