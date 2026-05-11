"""TIBET Drop .tza bundle pack/verify.

Per Phase 0 spec (phase-0-tza-bundle-format.md):
- TBZ-compatible block layout
- Manifest as block 0 (NOT in blocks list per spec §2.2.1)
- Per-block content_sha256 + Ed25519 sig
- manifest_sig over canonical(manifest_without_sig)
"""
from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import cbor2

from .crypto import IdentityKey, sha256, sha256_hex, verify_signature
from .handshake import tpid_str


def _canonical_cbor(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class BlockEntry:
    index: int
    name: str
    content_sha256: str
    size_bytes: int
    ed25519_sig: str  # hex


def _sign_block(name: str, index: int, content_hash: bytes,
                signer: IdentityKey) -> bytes:
    """Per-block sig over (content_sha256 || name || index)."""
    payload = content_hash + name.encode() + struct.pack(">I", index)
    return signer.sign(payload)


def pack_bundle(
    output_path: Path,
    blocks: list[tuple[str, bytes]],
    sender_aint: str,
    sender_signer: IdentityKey,
    receiver_aint: str,
    receiver_pubkey_hex: str,
    payload_type: str,
    tpid: bytes,
    transfer_out_token_id: str | None = None,
    surface_time_fragment: str | None = None,
    surface_context: str | None = None,
    surface_profile: str | None = None,
    surface_priority: str | None = None,
) -> dict:
    """Pack a TIBET Drop .tza bundle.

    blocks: list of (name, content_bytes) tuples.
    Returns the manifest dict.

    Optional Semantic Surface Manifest fields (surface_*) mirror the
    external filename routing layer per phase-0-tza-bundle-format §2.2.
    All four are optional; if any is set, all four SHOULD be set so
    that filename ↔ manifest consistency checks remain meaningful.
    """
    block_entries = []
    for i, (name, content) in enumerate(blocks, start=1):
        h = sha256(content)
        sig = _sign_block(name, i, h, sender_signer)
        block_entries.append({
            "index": i,
            "name": name,
            "content_sha256": h.hex(),
            "size_bytes": len(content),
            "ed25519_sig": sig.hex(),
        })

    manifest = {
        "tbz_format_version": 1,
        "airdrop_format_version": 1,
        "tpid": tpid_str(tpid),
        "sender_aint": sender_aint,
        "sender_pubkey": sender_signer.pub_bytes().hex(),
        "receiver_aint": receiver_aint,
        "receiver_pubkey": receiver_pubkey_hex,
        "payload_type": payload_type,
        "block_count": len(blocks) + 1,  # blocks + manifest
        "blocks": block_entries,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "transfer_out_token_id": transfer_out_token_id,
    }

    # Semantic Surface Manifest mirroring (optional, v1).
    # Only emit when explicitly provided.
    if surface_time_fragment is not None:
        manifest["surface_time_fragment"] = surface_time_fragment
    if surface_context is not None:
        manifest["surface_context"] = surface_context
    if surface_profile is not None:
        manifest["surface_profile"] = surface_profile
    if surface_priority is not None:
        manifest["surface_priority"] = surface_priority

    # Sign manifest per spec §2.2.1 RULE 4
    canonical = _canonical_cbor(manifest)
    manifest["manifest_sig"] = sender_signer.sign(canonical).hex()

    # Serialize: [TBZ magic 3B][1B reserved=0x01]
    #            [4B total_blocks][4B mlen][manifest][4B blen][block]...
    # Magic-byte prefix per TBZ spec — required for sniff-stage
    # recognition by tibet-continuityd and other intake-pipelines.
    buf = bytearray()
    buf += b"\x54\x42\x5A\x01"   # "TBZ" + version=0x01
    total = len(blocks) + 1
    buf += struct.pack(">I", total)

    manifest_bytes = _canonical_cbor(manifest)
    buf += struct.pack(">I", len(manifest_bytes)) + manifest_bytes

    for _, content in blocks:
        buf += struct.pack(">I", len(content)) + content

    output_path.write_bytes(bytes(buf))
    return manifest


def verify_bundle(
    bundle_path: Path,
    seen_tpids: set[str] | None = None,
) -> tuple[bool, dict, list[str]]:
    """Verify a .tza bundle.

    Returns (valid, manifest_dict, errors_list).
    """
    errors = []
    if not bundle_path.exists():
        return False, {}, [f"File not found: {bundle_path}"]

    raw = bundle_path.read_bytes()
    if len(raw) < 12:
        return False, {}, ["File too small to be a valid .tza"]

    pos = 0
    # TBZ magic prefix (3B "TBZ" + 1B version, total 4B)
    if raw[0:3] == b"\x54\x42\x5A":
        pos += 4   # skip TBZ + version byte
    # else: legacy bundle without magic prefix; continue at pos=0

    total = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4

    mlen = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4
    manifest_bytes = raw[pos:pos + mlen]
    pos += mlen

    try:
        manifest = cbor2.loads(manifest_bytes)
    except Exception as e:
        return False, {}, [f"Manifest CBOR decode failed: {e}"]

    # Verify manifest_sig
    sig_hex = manifest.get("manifest_sig")
    if not sig_hex:
        errors.append("Missing manifest_sig")
        return False, manifest, errors

    sender_pubkey_hex = manifest.get("sender_pubkey")
    if not sender_pubkey_hex:
        errors.append("Missing sender_pubkey")
        return False, manifest, errors

    tpid = manifest.get("tpid")
    if seen_tpids is not None and tpid in seen_tpids:
        errors.append(f"replayed tpid detected: {tpid}")
        return False, manifest, errors

    manifest_no_sig = {k: v for k, v in manifest.items()
                        if k != "manifest_sig"}
    canonical = _canonical_cbor(manifest_no_sig)
    sender_pubkey = bytes.fromhex(sender_pubkey_hex)
    sig = bytes.fromhex(sig_hex)

    if not verify_signature(sender_pubkey, canonical, sig):
        errors.append("manifest_sig verification failed")
        return False, manifest, errors

    # Verify each block
    block_specs = manifest.get("blocks", [])
    if total - 1 != len(block_specs):
        errors.append(f"block_count mismatch: header={total} manifest={len(block_specs) + 1}")

    for expected_index, spec in enumerate(block_specs, start=1):
        if spec.get("index") != expected_index:
            errors.append(
                f"block index mismatch in manifest: expected {expected_index} got {spec.get('index')}"
            )
        if pos + 4 > len(raw):
            errors.append(f"truncated bundle at block {spec['index']}")
            break
        blen = struct.unpack(">I", raw[pos:pos + 4])[0]
        pos += 4
        if pos + blen > len(raw):
            errors.append(f"truncated bundle content at block {spec['index']}")
            break
        block_content = raw[pos:pos + blen]
        pos += blen

        actual_hash = sha256_hex(block_content)
        if actual_hash != spec["content_sha256"]:
            errors.append(
                f"block {spec['index']} ({spec['name']}): hash mismatch"
            )
            continue

        # Verify per-block sig
        h = bytes.fromhex(spec["content_sha256"])
        sig_payload = h + spec["name"].encode() + struct.pack(">I", spec["index"])
        block_sig = bytes.fromhex(spec["ed25519_sig"])
        if not verify_signature(sender_pubkey, sig_payload, block_sig):
            errors.append(
                f"block {spec['index']} ({spec['name']}): per-block sig failed"
            )

    if pos != len(raw):
        errors.append(f"trailing or unread bytes detected: consumed={pos} total={len(raw)}")

    return len(errors) == 0, manifest, errors


def parse_filename_surface(name: str) -> dict | None:
    """Parse a Semantic Surface Manifest from a filename.

    Expected form (per spec §6.1):
        <time-fragment>.<context>.<profile>.<priority>[.<icc-ext>]

    Returns dict with surface_* fields if 4+ dot-separated segments
    match the v1 character policy [a-z0-9-], else None.
    """
    import re
    stem = name.rsplit(".tza", 1)[0] if name.endswith(".tza") else name
    # strip any single .ICC-ext suffix (e.g. .claude / .gemini / .kit)
    parts = stem.split(".")
    if len(parts) < 4:
        return None
    pattern = re.compile(r"^[a-z0-9-]+$")
    if not all(pattern.match(p) for p in parts[:4]):
        return None
    return {
        "surface_time_fragment": parts[0],
        "surface_context": parts[1],
        "surface_profile": parts[2],
        "surface_priority": parts[3],
    }


def compare_surfaces(
    filename_surface: dict | None,
    manifest_surface: dict | None,
) -> str:
    """Return one of: MATCH, MISMATCH, PARTIAL, NONE.

    NONE   = neither side has surface_* fields (legacy bundle)
    MATCH  = all four fields equal on both sides
    PARTIAL = filename has fields but manifest absent (or vice versa)
    MISMATCH = both present but at least one field differs
    """
    keys = (
        "surface_time_fragment",
        "surface_context",
        "surface_profile",
        "surface_priority",
    )
    fn_present = filename_surface is not None
    mf_present = manifest_surface is not None and any(
        manifest_surface.get(k) is not None for k in keys
    )

    if not fn_present and not mf_present:
        return "NONE"
    if fn_present != mf_present:
        return "PARTIAL"

    for k in keys:
        if filename_surface.get(k) != manifest_surface.get(k):
            return "MISMATCH"
    return "MATCH"


def inspect_bundle(bundle_path: Path) -> dict:
    """Read and return the manifest without full verification."""
    raw = bundle_path.read_bytes()
    pos = 0
    if raw[0:3] == b"\x54\x42\x5A":
        pos += 4   # skip TBZ magic + version byte
    _total = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4
    mlen = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4
    return cbor2.loads(raw[pos:pos + mlen])


def unpack_bundle(bundle_path: Path, output_dir: Path) -> dict:
    """Extract blocks to output_dir. Returns manifest."""
    raw = bundle_path.read_bytes()
    pos = 0
    if raw[0:3] == b"\x54\x42\x5A":
        pos += 4   # skip TBZ magic + version byte
    total = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4

    mlen = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4
    manifest = cbor2.loads(raw[pos:pos + mlen])
    pos += mlen

    output_dir.mkdir(parents=True, exist_ok=True)

    for spec in manifest.get("blocks", []):
        blen = struct.unpack(">I", raw[pos:pos + 4])[0]
        pos += 4
        content = raw[pos:pos + blen]
        pos += blen

        target = output_dir / spec["name"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    return manifest
