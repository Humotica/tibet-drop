"""TIBET Drop CLI — tibet-drop subcommands.

Patterns after tibet-zip-cli; subcommands include:
- init      Generate a keypair + .aint stub
- pack      Build a .tza bundle (sender side)
- verify    Verify a .tza bundle
- inspect   Show manifest of a .tza bundle
- unpack    Extract blocks from a .tza bundle
- handshake Generate UPIP-seed for mock NFC handshake
- demo      End-to-end mock airdrop demonstration
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .bundle import (
    compare_surfaces,
    inspect_bundle,
    pack_bundle,
    parse_filename_surface,
    unpack_bundle,
    verify_bundle,
)
from .crypto import IdentityKey, sha256_hex
from .handshake import (
    SendSeed,
    decode_seed,
    new_tpid,
    tpid_str,
    verify_seed,
)
from .tokens import TombstoneToken, TransferInToken, TransferOutToken


def cmd_init(args: argparse.Namespace) -> int:
    """Generate fresh keypair + .aint identity claim."""
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    key = IdentityKey.generate()
    priv_bytes = key.priv.private_bytes_raw()
    pub_bytes = key.pub_bytes()

    (out_dir / "identity.priv").write_bytes(priv_bytes)
    (out_dir / "identity.pub").write_bytes(pub_bytes)
    (out_dir / "identity.json").write_text(json.dumps({
        "aint": args.aint,
        "pubkey_hex": pub_bytes.hex(),
        "fingerprint_hex": key.fingerprint().hex(),
    }, indent=2))

    print(f"✓ Generated identity for {args.aint}")
    print(f"  Pubkey: {pub_bytes.hex()}")
    print(f"  Fingerprint: {key.fingerprint().hex()}")
    print(f"  Stored in: {out_dir}")
    return 0


def _load_identity(identity_dir: Path) -> tuple[IdentityKey, str]:
    """Load IdentityKey from a dir produced by cmd_init."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv_bytes = (identity_dir / "identity.priv").read_bytes()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    info = json.loads((identity_dir / "identity.json").read_text())
    return IdentityKey(priv=priv, pub=priv.public_key()), info["aint"]


def cmd_pack(args: argparse.Namespace) -> int:
    """Pack a directory into a .tza bundle."""
    sender_dir = Path(args.identity)
    signer, sender_aint = _load_identity(sender_dir)

    receiver_pub_hex = args.receiver_pubkey
    receiver_aint = args.receiver_aint

    src = Path(args.input)
    if not src.exists():
        print(f"Error: input not found: {src}", file=sys.stderr)
        return 1

    blocks: list[tuple[str, bytes]] = []
    if src.is_file():
        blocks.append((src.name, src.read_bytes()))
    else:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                rel = path.relative_to(src)
                blocks.append((str(rel), path.read_bytes()))

    if not blocks:
        print(f"Error: no files to pack in {src}", file=sys.stderr)
        return 1

    tpid = new_tpid() if not args.tpid else bytes.fromhex(args.tpid)
    output_path = Path(args.output)

    # Resolve surface fields (per Semantic Surface Manifest spec §6).
    surface_time = args.surface_time
    if surface_time == "auto":
        import time as _time
        surface_time = _time.strftime("%Y-%m-%d", _time.gmtime())
    surface_profile = args.surface_profile
    if surface_profile is None and args.payload_type:
        # Sensible default: derive profile from payload-type tag.
        profile_map = {
            "ai_state": "tza",
            "identity_only": "iddrop",
            "vc": "parentattest",
            "capsule": "capsule",
            "file": "filedrop",
        }
        surface_profile = profile_map.get(args.payload_type)

    manifest = pack_bundle(
        output_path=output_path,
        blocks=blocks,
        sender_aint=sender_aint,
        sender_signer=signer,
        receiver_aint=receiver_aint,
        receiver_pubkey_hex=receiver_pub_hex,
        payload_type=args.payload_type,
        tpid=tpid,
        surface_time_fragment=surface_time,
        surface_context=args.surface_context,
        surface_profile=surface_profile,
        surface_priority=args.surface_priority,
    )

    print(f"✓ Packed {len(blocks)} block(s) → {output_path}")
    print(f"  tpid: {manifest['tpid']}")
    print(f"  payload_type: {manifest['payload_type']}")
    if "surface_profile" in manifest:
        surface_str = ".".join([
            manifest.get("surface_time_fragment", "?"),
            manifest.get("surface_context", "?"),
            manifest.get("surface_profile", "?"),
            manifest.get("surface_priority", "?"),
        ])
        print(f"  surface: {surface_str}")
    print(f"  total bytes: {output_path.stat().st_size}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a .tza bundle (with surface consistency check)."""
    bundle = Path(args.bundle)
    valid, manifest, errors = verify_bundle(bundle)

    # Semantic Surface consistency check (RULE 6).
    fn_surface = parse_filename_surface(bundle.name)
    mf_surface = {
        k: manifest.get(k) for k in (
            "surface_time_fragment",
            "surface_context",
            "surface_profile",
            "surface_priority",
        )
        if manifest.get(k) is not None
    } or None
    surface_status = compare_surfaces(fn_surface, mf_surface)

    print(f"Bundle: {bundle}")
    print(f"  tpid: {manifest.get('tpid', '?')}")
    print(f"  sender: {manifest.get('sender_aint', '?')}")
    print(f"  receiver: {manifest.get('receiver_aint', '?')}")
    print(f"  payload_type: {manifest.get('payload_type', '?')}")
    print(f"  blocks: {len(manifest.get('blocks', []))}")

    if surface_status == "NONE":
        print("  semantic surface: ABSENT")
    else:
        print(f"  semantic surface: PRESENT")
        print(f"  surface consistency: {surface_status}")
        if surface_status == "MISMATCH":
            print("  verifier disposition: TRIAGE  ⚠")
            print("    (sealed bundle valid, but routing-layer anomaly —")
            print("     causal isolation recommended per spec §11)")

    if valid:
        if surface_status == "MISMATCH":
            print("⚠ Bundle integrity OK but surface mismatch (triage)")
            return 2
        print("✓ Bundle valid (manifest sig + per-block sigs verified)")
        return 0
    else:
        print("✗ Bundle invalid:")
        for e in errors:
            print(f"   • {e}")
        return 1


def cmd_inspect(args: argparse.Namespace) -> int:
    """Print bundle metadata; --json emits raw manifest."""
    bundle = Path(args.bundle)
    manifest = inspect_bundle(bundle)

    if args.json_output:
        print(json.dumps(manifest, indent=2, default=str))
        return 0

    # Pretty header form (per Semantic Surface tooling-sketch §1).
    print(f"Bundle: {bundle.name}")
    print(f"  Magic:           TBZ v1")
    print(f"  Format:          tza-airdrop-{manifest.get('airdrop_format_version', '?')}")
    print(f"  tpid:            {manifest.get('tpid', '?')}")
    print(f"  sender:          {manifest.get('sender_aint', '?')}")
    print(f"  receiver:        {manifest.get('receiver_aint', '?')}")
    print(f"  payload_type:    {manifest.get('payload_type', '?')}")
    print(f"  blocks:          {len(manifest.get('blocks', []))}")

    surface_keys = (
        "surface_time_fragment",
        "surface_context",
        "surface_profile",
        "surface_priority",
    )
    has_surface = any(manifest.get(k) is not None for k in surface_keys)
    if has_surface:
        print(f"  Surface time:    {manifest.get('surface_time_fragment', '—')}")
        print(f"  Surface context: {manifest.get('surface_context', '—')}")
        print(f"  Surface profile: {manifest.get('surface_profile', '—')}")
        print(f"  Surface priority: {manifest.get('surface_priority', '—')}")

        fn_surface = parse_filename_surface(bundle.name)
        mf_surface = {k: manifest.get(k) for k in surface_keys
                       if manifest.get(k) is not None} or None
        status = compare_surfaces(fn_surface, mf_surface)
        marker = "✓" if status == "MATCH" else "⚠"
        print(f"  Surface consistency: {status} {marker}")
        if status == "MISMATCH":
            print("    (filename and manifest surface_* differ;")
            print("     triage fork recommended per spec §11)")
    else:
        print("  Semantic surface: ABSENT (legacy bundle)")
    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    """Extract bundle contents to a directory."""
    bundle = Path(args.bundle)
    out = Path(args.out)
    manifest = unpack_bundle(bundle, out)
    print(f"✓ Unpacked {len(manifest.get('blocks', []))} block(s) → {out}")
    return 0


def cmd_handshake(args: argparse.Namespace) -> int:
    """Generate a UPIP-seed for mock NFC handshake."""
    sender_dir = Path(args.identity)
    signer, aint = _load_identity(sender_dir)

    from .crypto import EphemeralKey

    eph = EphemeralKey.generate()
    tpid = new_tpid()
    intent = {
        "payload": args.payload_type,
        "size": args.size_hint,
        "wipe": args.wipe,
    }

    seed = SendSeed(
        aint=aint,
        pk_from=signer.pub_bytes(),
        epk_from=eph.pub_bytes(),
        tpid=tpid,
        intent=intent,
    )
    encoded = seed.encode(signer)

    output_path = Path(args.output)
    output_path.write_bytes(encoded)

    # Save ephemeral private key for receiver-side workflow
    eph_priv_path = output_path.with_suffix(".eph.priv")
    from cryptography.hazmat.primitives import serialization
    eph_priv_bytes = eph.priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    eph_priv_path.write_bytes(eph_priv_bytes)

    print(f"✓ UPIP-seed generated → {output_path}")
    print(f"  size: {len(encoded)} bytes ({len(encoded)}/512 budget)")
    print(f"  tpid: {tpid_str(tpid)}")
    print(f"  ephemeral priv stored: {eph_priv_path} (keep secret)")
    return 0


def cmd_seed_inspect(args: argparse.Namespace) -> int:
    """Decode and verify a UPIP-seed file."""
    blob = Path(args.seed).read_bytes()
    valid, body, err = verify_seed(blob)

    print(f"Seed: {args.seed}")
    print(f"  size: {len(blob)} bytes")
    print(f"  kind: {body.get('kind')}")
    print(f"  from: {body.get('from')}")
    print(f"  tpid: {tpid_str(body.get('tpid', b''))}")
    print(f"  intent: {body.get('intent')}")
    if valid:
        print("✓ Signature valid")
        return 0
    else:
        print(f"✗ Invalid: {err}")
        return 1


def cmd_demo(args: argparse.Namespace) -> int:
    """End-to-end mock TIBET Drop airdrop demonstration."""
    from .demo import run_demo
    return run_demo(verbose=args.verbose)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tibet-drop",
        description=(
            "TIBET Drop — identity-bound device-to-device payload transfer. "
            "Reference Python implementation of TIBET TAT (Touch-And-Transfer)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Generate keypair + .aint identity")
    p_init.add_argument("--aint", required=True, help=".aint identity name")
    p_init.add_argument("--out", required=True, help="Output directory")
    p_init.set_defaults(func=cmd_init)

    p_pack = sub.add_parser("pack", help="Build a .tza bundle")
    p_pack.add_argument("--identity", required=True, help="Sender identity dir")
    p_pack.add_argument("--receiver-aint", required=True)
    p_pack.add_argument("--receiver-pubkey", required=True, help="Hex Ed25519 pubkey")
    p_pack.add_argument("--input", required=True, help="File or directory to pack")
    p_pack.add_argument("--output", required=True, help="Output .tza path")
    p_pack.add_argument("--payload-type", default="ai_state",
                         choices=["ai_state", "identity_only", "vc", "capsule", "file"])
    p_pack.add_argument("--tpid", help="Optional explicit tpid (hex)")
    # Semantic Surface Manifest fields (optional, per spec §6).
    p_pack.add_argument("--surface-context",
                         help="Routing context label (e.g. redspecter-review)")
    p_pack.add_argument("--surface-profile",
                         help="Semantic profile (claude/gemini/kit/iddrop/parentattest/capsule/tza). "
                              "Defaults derived from --payload-type.")
    p_pack.add_argument("--surface-priority",
                         choices=["urgent", "normal", "background",
                                  "sealed", "heartbeat"],
                         help=(
                             "Dispatch priority. 'heartbeat' (= v0.6.3+) "
                             "marks a liveness/shutdown signal: receivers "
                             "that recognize the identity pin MAY route "
                             "to a log-only lane (skip Fork/Seal/Police)."
                         ))
    p_pack.add_argument("--surface-time", default="auto",
                         help='ISO8601 fragment or "auto" (today UTC). v1 uses YYYY-MM-DD.')
    p_pack.set_defaults(func=cmd_pack)

    p_verify = sub.add_parser("verify", help="Verify a .tza bundle")
    p_verify.add_argument("bundle", help="Path to .tza bundle")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="Print manifest of a .tza bundle")
    p_inspect.add_argument("bundle", help="Path to .tza bundle")
    p_inspect.add_argument("--json", dest="json_output", action="store_true",
                            help="Emit raw manifest as JSON")
    p_inspect.set_defaults(func=cmd_inspect)

    p_unpack = sub.add_parser("unpack", help="Extract a .tza bundle")
    p_unpack.add_argument("bundle", help="Path to .tza bundle")
    p_unpack.add_argument("--out", required=True, help="Output directory")
    p_unpack.set_defaults(func=cmd_unpack)

    p_hs = sub.add_parser("handshake", help="Generate UPIP-seed (mock NFC)")
    p_hs.add_argument("--identity", required=True, help="Sender identity dir")
    p_hs.add_argument("--output", required=True, help="Output seed file")
    p_hs.add_argument("--payload-type", default="ai_state",
                       choices=["ai_state", "identity_only", "vc", "capsule", "file"])
    p_hs.add_argument("--size-hint", type=int, default=0,
                       help="Estimated bundle size in bytes")
    p_hs.add_argument("--wipe", action="store_true",
                       help="Set wipe-after-handoff intent")
    p_hs.set_defaults(func=cmd_handshake)

    p_si = sub.add_parser("seed-inspect", help="Decode + verify UPIP-seed")
    p_si.add_argument("seed", help="Path to .seed file")
    p_si.set_defaults(func=cmd_seed_inspect)

    p_demo = sub.add_parser("demo", help="End-to-end mock airdrop demo")
    p_demo.add_argument("-v", "--verbose", action="store_true")
    p_demo.set_defaults(func=cmd_demo)

    p_send = sub.add_parser("send", help="Send a sealed bundle to an .aint inbox")
    p_send.add_argument("bundle", help="Path to .tza bundle to send")
    p_send.add_argument("--to", required=True, help="Recipient .aint")
    p_send.add_argument("--base", help="Override hub base URL")
    p_send.add_argument("--ainternet", action="store_true",
                        help="Use api.ainternet.org")
    p_send.add_argument("--brein", action="store_true",
                        help="Use brein.jaspervandemeent.nl")
    p_send.set_defaults(func=cmd_send)

    p_recv = sub.add_parser("recv",
                            help="Receive (arrival-gated) from your .aint inbox")
    p_recv.add_argument("aint", help="Your .aint (inbox to receive from)")
    p_recv.add_argument("--out", help="Directory to unpack the accepted bundle into")
    p_recv.add_argument("--raw", action="store_true",
                        help="Bypass the gate; raw ungated /pull")
    p_recv.add_argument("--base", help="Override hub base URL")
    p_recv.add_argument("--ainternet", action="store_true")
    p_recv.add_argument("--brein", action="store_true")
    p_recv.set_defaults(func=cmd_recv)

    return parser


# ── Transport: send / recv over the iddrop inbox ────────────────────
# The bundle is the security (TBZ self-authenticates), so transport is a
# thin POST/GET over the brain-api iddrop inbox. send POSTs a sealed
# bundle; recv runs the arrival-gate (sniff/verify/policy/trace) by
# default, or --raw for an ungated pull.

_HUBS = {
    "local": "http://localhost:8000",
    "ainternet": "https://api.ainternet.org",
    "brein": "https://brein.jaspervandemeent.nl",
}


def _resolve_base(args: argparse.Namespace) -> str:
    if getattr(args, "base", None):
        return args.base.rstrip("/")
    if getattr(args, "ainternet", False):
        return _HUBS["ainternet"]
    if getattr(args, "brein", False):
        return _HUBS["brein"]
    return _HUBS["local"]


def _norm_aint(aint: str) -> str:
    s = aint.strip().lower()
    return s[:-5] if s.endswith(".aint") else s


def _http(method: str, url: str, data: bytes | None = None,
          ctype: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method)
    # Explicit User-Agent — api.ainternet.org's WAF rejects blank UAs.
    req.add_header("User-Agent", "tibet-drop/transport")
    if ctype:
        req.add_header("Content-Type", ctype)
    # Timeout env-tunable: big sealed carriers (tens of MB) need more than the
    # default 15s to finish the upload write. TIBET_DROP_TIMEOUT overrides (seconds).
    _timeout = float(os.environ.get("TIBET_DROP_TIMEOUT", "15"))
    try:
        with urllib.request.urlopen(req, timeout=_timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return 0, str(e).encode()


def cmd_send(args: argparse.Namespace) -> int:
    """POST a sealed bundle to a recipient .aint inbox."""
    bundle = Path(args.bundle)
    if not bundle.is_file():
        print(f"✗ bundle not found: {bundle}", file=sys.stderr)
        return 2
    data = bundle.read_bytes()
    base = _resolve_base(args)
    aint = _norm_aint(args.to)
    code, body = _http("POST", f"{base}/api/iddrop/inbox/{aint}",
                       data=data, ctype="application/octet-stream")
    try:
        j = json.loads(body)
    except Exception:
        j = {"raw": body[:200].decode("utf-8", "replace")}
    if code == 200 and j.get("status") == "accepted":
        print(f"✓ sent {len(data)} bytes → {aint} @ {base}")
        print(f"  envelope_id: {j.get('envelope_id')}")
        return 0
    print(f"✗ send failed (HTTP {code}): {j}", file=sys.stderr)
    return 1


def cmd_recv(args: argparse.Namespace) -> int:
    """Receive from your .aint inbox — arrival-gated by default."""
    base = _resolve_base(args)
    aint = _norm_aint(args.aint)

    if args.raw:
        code, body = _http("GET", f"{base}/api/iddrop/inbox/{aint}/pull")
        if code == 204:
            print("· inbox empty")
            return 0
        if code != 200:
            print(f"✗ pull failed (HTTP {code})", file=sys.stderr)
            return 1
        out = Path(args.out or f"{aint}-envelope.tza")
        out.write_bytes(body)
        print(f"✓ pulled {len(body)} bytes (raw, ungated) → {out}")
        return 0

    code, body = _http("GET", f"{base}/api/iddrop/inbox/{aint}/receive")
    try:
        j = json.loads(body)
    except Exception:
        print(f"✗ unexpected response (HTTP {code}): {body[:200]!r}",
              file=sys.stderr)
        return 1

    verdict = j.get("verdict")
    if verdict == "empty":
        print("· inbox empty")
        return 0
    if verdict == "rejected":
        print(f"✗ REJECTED by arrival-gate (HTTP {code}):")
        for r in j.get("reasons", []):
            print(f"  - {r}")
        print(f"  quarantined: {j.get('quarantined')}  trace: {j.get('trace')}")
        return 1
    if verdict != "accepted":
        print(f"? unknown verdict: {verdict}", file=sys.stderr)
        return 1

    print(f"✓ ACCEPTED from {j.get('sender_aint')} "
          f"(trust {j.get('sender_trust')})")
    print(f"  payload_type: {j.get('payload_type')}  "
          f"materialize: {j.get('materialize')}")
    print(f"  arrival_token: {j.get('arrival_token_id')}  "
          f"← transfer_out: {j.get('transfer_out_token_id')}")

    b64 = j.get("bundle_b64")
    if not b64:
        print("  (no bundle bytes returned)")
        return 0
    raw = base64.b64decode(b64)

    if args.out:
        outdir = Path(args.out)
        with tempfile.NamedTemporaryFile(suffix=".tza", delete=False) as tf:
            tf.write(raw)
            tmp = Path(tf.name)
        try:
            manifest = unpack_bundle(tmp, outdir)
            print(f"  unpacked {len(manifest.get('blocks', []))} "
                  f"block(s) → {outdir}")
        finally:
            tmp.unlink(missing_ok=True)
    else:
        save = Path(f"{aint}-received.tza")
        save.write_bytes(raw)
        print(f"  saved sealed bundle → {save} "
              f"(use `tibet-drop unpack` to extract)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
