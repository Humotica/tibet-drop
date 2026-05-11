"""End-to-end TIBET Drop demonstration (mock NFC + mock Wi-Fi Direct).

Demonstrates the full TIBET TAT wire protocol:
  1. Alice + Bob generate identities
  2. Mock NFC handshake (UPIP-seed bidirectional)
  3. ECDH key derivation (both sides arrive at same tunnel_key)
  4. Alice writes transfer_out token (chain-anchored)
  5. Alice packs .tza bundle
  6. Mock tunnel: bundle encrypted with AES-256-GCM, streamed in chunks
  7. Bob decrypts + verifies bundle
  8. Bob writes transfer_in token (with generation inheritance)
  9. Tombstone optional (Story 1 Wipe variant)
"""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

from .bundle import (
    compare_surfaces,
    pack_bundle,
    parse_filename_surface,
    verify_bundle,
)
from .crypto import (
    EphemeralKey,
    IdentityKey,
    decrypt_chunk,
    derive_tunnel_keys,
    encrypt_chunk,
    sha256,
    sha256_hex,
)
from .handshake import (
    RecvSeed,
    SendSeed,
    decode_seed,
    new_tpid,
    tpid_str,
    verify_seed,
)
from .tokens import (
    TombstoneToken,
    TransferInToken,
    TransferOutToken,
)


CHUNK_SIZE = 64 * 1024  # 64 KB per Phase 0 spec


def _step(verbose: bool, name: str, msg: str) -> None:
    if verbose:
        print(f"  [{name}] {msg}")


def run_demo(verbose: bool = False) -> int:
    print()
    print("═" * 64)
    print("  TIBET DROP — End-to-End Mock Airdrop Demo")
    print("  (TIBET TAT Touch-And-Transfer protocol, Phase 0 spec)")
    print("═" * 64)
    print()

    # ─── Step 1: Identities ────────────────────────────────────
    print("STEP 1 — Generate identities")
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    print(f"  Alice fp: {alice.fingerprint().hex()[:16]}...")
    print(f"  Bob fp:   {bob.fingerprint().hex()[:16]}...")

    # ─── Step 2: NFC handshake — both seeds ────────────────────
    print()
    print("STEP 2 — Mock NFC handshake (UPIP-seed exchange)")
    tpid = new_tpid()
    print(f"  tpid: {tpid_str(tpid)}")

    alice_eph = EphemeralKey.generate()
    bob_eph = EphemeralKey.generate()

    seed_send = SendSeed(
        aint="alice.aint",
        pk_from=alice.pub_bytes(),
        epk_from=alice_eph.pub_bytes(),
        tpid=tpid,
        intent={"payload": "ai_state", "size": 0, "wipe": True},
    )
    seed_send_bytes = seed_send.encode(alice)

    valid_send, _, _ = verify_seed(seed_send_bytes)
    _step(verbose, "alice→bob seed", f"{len(seed_send_bytes)} bytes, sig valid={valid_send}")

    seed_recv = RecvSeed(
        aint="bob.aint",
        pk_from=bob.pub_bytes(),
        epk_from=bob_eph.pub_bytes(),
        tpid=tpid,
        consent="accept",
    )
    seed_recv_bytes = seed_recv.encode(bob)

    valid_recv, _, _ = verify_seed(seed_recv_bytes)
    _step(verbose, "bob→alice seed", f"{len(seed_recv_bytes)} bytes, sig valid={valid_recv}")

    if not (valid_send and valid_recv):
        print("✗ Handshake signature failed")
        return 1
    print("  ✓ Both seeds signed + verified")

    # ─── Step 3: ECDH key derivation ───────────────────────────
    print()
    print("STEP 3 — ECDH key derivation")
    alice_tk, alice_np = derive_tunnel_keys(alice_eph, bob_eph.pub_bytes(), tpid)
    bob_tk, bob_np = derive_tunnel_keys(bob_eph, alice_eph.pub_bytes(), tpid)

    if alice_tk != bob_tk:
        print("✗ Tunnel keys differ between Alice and Bob!")
        return 1
    if alice_np != bob_np:
        print("✗ Nonce prefixes differ!")
        return 1
    print(f"  ✓ tunnel_key (32B) match: {alice_tk.hex()[:16]}...")
    print(f"  ✓ nonce_prefix (8B) match: {alice_np.hex()}")

    # ─── Step 4: transfer_out token (chain-anchored) ───────────
    print()
    print("STEP 4 — Alice writes transfer_out token")
    transfer_out = TransferOutToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        receiver_aint="bob.aint",
        receiver_fp=bob.fingerprint(),
        payload_type="ai_state",
        payload_summary={"size_bytes": 0, "content_sha256": "pending", "memory_count": 12},
        transfer_pair_id=tpid,
        generation=42,  # alice's current chain generation (mock)
        session_ephemeral_pubkey=alice_eph.pub_bytes(),
    )
    out_token = transfer_out.to_dict(alice)
    _step(verbose, "transfer_out", f"token_id={out_token['token_id'][:8]}... gen={out_token['generation']}")
    print(f"  ✓ transfer_out chained (gen={out_token['generation']})")

    # ─── Step 5: Pack bundle ────────────────────────────────────
    print()
    print("STEP 5 — Alice packs .tza bundle")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        sender_state = tmp_path / "alice-state"
        sender_state.mkdir()
        (sender_state / "persona.txt").write_text(
            "Persona: Alice's helpful assistant.\nTier: verified\n"
        )
        (sender_state / "chat-history.txt").write_text(
            "Chat 1: greeting\nChat 2: bug help\n" * 100
        )
        (sender_state / "memories.json").write_text(json.dumps({
            "count": 12,
            "highlights": ["birthday-2024", "work-launch", "iceland-trip"]
        }))

        blocks = []
        for f in sorted(sender_state.rglob("*")):
            if f.is_file():
                rel = f.relative_to(sender_state)
                blocks.append((str(rel), f.read_bytes()))

        # Filename mirrors Semantic Surface Manifest fields per spec §6.1
        bundle_name = "2026-05-09.airdrop-demo.claude.urgent.tza"
        bundle_path = tmp_path / bundle_name
        manifest = pack_bundle(
            output_path=bundle_path,
            blocks=blocks,
            sender_aint="alice.aint",
            sender_signer=alice,
            receiver_aint="bob.aint",
            receiver_pubkey_hex=bob.pub_bytes().hex(),
            payload_type="ai_state",
            tpid=tpid,
            transfer_out_token_id=out_token["token_id"],
            surface_time_fragment="2026-05-09",
            surface_context="airdrop-demo",
            surface_profile="claude",
            surface_priority="urgent",
        )
        print(f"  ✓ Filename: {bundle_name}")
        print(f"    surface_*: 2026-05-09 / airdrop-demo / claude / urgent")

        bundle_bytes = bundle_path.read_bytes()
        bundle_hash = sha256_hex(bundle_bytes)
        print(f"  ✓ Packed {len(blocks)} block(s), {len(bundle_bytes)} bytes")
        print(f"  ✓ Bundle SHA-256: {bundle_hash[:16]}...")

        # ─── Step 6: Mock tunnel transfer ──────────────────────
        print()
        print("STEP 6 — Mock Wi-Fi Direct tunnel (AES-256-GCM streaming)")
        chunks = []
        for i in range(0, len(bundle_bytes), CHUNK_SIZE):
            chunk = bundle_bytes[i:i + CHUNK_SIZE]
            idx = i // CHUNK_SIZE
            aad = tpid + struct.pack(">I", idx) + struct.pack(">I", -(-len(bundle_bytes) // CHUNK_SIZE))
            ct = encrypt_chunk(alice_tk, alice_np, idx, chunk, aad)
            chunks.append(ct)
            _step(verbose, f"chunk {idx}", f"{len(chunk)}B plaintext → {len(ct)}B ciphertext")

        print(f"  ✓ Streamed {len(chunks)} encrypted chunk(s)")

        # ─── Step 7: Bob decrypts + verifies ───────────────────
        print()
        print("STEP 7 — Bob decrypts + verifies")
        recovered = bytearray()
        total_chunks = len(chunks)
        for idx, ct in enumerate(chunks):
            aad = tpid + struct.pack(">I", idx) + struct.pack(">I", total_chunks)
            pt = decrypt_chunk(bob_tk, bob_np, idx, ct, aad)
            recovered.extend(pt)
        recovered = bytes(recovered)

        if recovered != bundle_bytes:
            print("✗ Recovered bundle bytes differ from original!")
            return 1
        print(f"  ✓ Bundle bytes recovered intact ({len(recovered)} bytes)")

        recovered_hash = sha256_hex(recovered)
        if recovered_hash != bundle_hash:
            print("✗ Recovered bundle SHA-256 mismatch!")
            return 1
        print(f"  ✓ SHA-256 matches sender's claim")

        # Bob writes recovered bundle (preserving the surface-aware filename)
        # and runs verifier.
        bob_bundle = tmp_path / bundle_name
        bob_bundle.write_bytes(recovered)
        valid, manifest_check, errs = verify_bundle(bob_bundle)
        if not valid:
            print(f"✗ Bundle verification failed: {errs}")
            return 1
        print(f"  ✓ Bundle manifest_sig + per-block sigs verified")

        # Surface consistency check (filename ↔ manifest, spec §11)
        fn_surface = parse_filename_surface(bob_bundle.name)
        mf_surface = {k: manifest_check.get(k) for k in (
            "surface_time_fragment", "surface_context",
            "surface_profile", "surface_priority")}
        status = compare_surfaces(fn_surface, mf_surface)
        if status != "MATCH":
            print(f"✗ Surface consistency unexpected: {status}")
            return 1
        print(f"  ✓ Surface consistency: MATCH (filename mirrors manifest)")

        # ─── Step 8: transfer_in token (Lamport inheritance) ──
        print()
        print("STEP 8 — Bob writes transfer_in token")
        transfer_in = TransferInToken(
            actor_aint="bob.aint",
            actor_pubkey=bob.pub_bytes(),
            sender_aint="alice.aint",
            sender_fp=alice.fingerprint(),
            payload_type="ai_state",
            payload_received={
                "size_bytes": len(recovered),
                "content_sha256": recovered_hash,
                "verified_at": "2026-05-08T10:00:00Z",
            },
            transfer_pair_id=tpid,
            sender_generation=42,  # from sender's transfer_out
            local_generation=10,    # Bob's existing chain gen
            sender_transfer_out_token_id=out_token["token_id"],
            session_ephemeral_pubkey=bob_eph.pub_bytes(),
        )
        in_token = transfer_in.to_dict(bob)
        # Lamport-style: max(10, 42) + 1 = 43
        print(f"  ✓ transfer_in chained")
        print(f"    Bob's local gen:        10")
        print(f"    Sender's reported gen:  42")
        print(f"    New gen (Lamport rule): {in_token['generation']}")

        # ─── Step 9: Tombstone (optional, Story 1 Wipe) ──────
        print()
        print("STEP 9 — Alice writes tombstone (Story 1 Wipe variant)")
        tombstone = TombstoneToken(
            actor_aint="alice.aint",
            actor_pubkey=alice.pub_bytes(),
            transfer_out_ref=out_token["token_id"],
            successor_aint="bob.aint",
            successor_fp=bob.fingerprint(),
            recovery_policy="destroyed",
            generation=43,
        )
        tomb_token = tombstone.to_dict(alice)
        print(f"  ✓ Tombstone chained ({tomb_token['eraan']['recovery_policy']})")
        print(f"    Successor: {tomb_token['eraan']['successor_device'][:48]}...")

        # ─── Step 10: Rename-attack detection ──────────────────
        print()
        print("STEP 10 — Adversary renames bundle (surface ≠ payload)")
        attacker_name = "2026-05-09.airdrop-demo.claude.normal.tza"
        renamed = tmp_path / attacker_name
        bob_bundle.rename(renamed)
        print(f"  Renamed: {bundle_name}")
        print(f"        → {attacker_name}")
        print(f"        (only --priority field swapped: urgent → normal)")

        valid_renamed, manifest_renamed, _ = verify_bundle(renamed)
        if not valid_renamed:
            print("✗ Sealed bundle should remain cryptographically valid!")
            return 1
        print(f"  ✓ Sealed bundle still cryptographically valid")
        print(f"    (manifest_sig + per-block sigs unchanged)")

        fn_surface_r = parse_filename_surface(renamed.name)
        mf_surface_r = {k: manifest_renamed.get(k) for k in (
            "surface_time_fragment", "surface_context",
            "surface_profile", "surface_priority")}
        status_r = compare_surfaces(fn_surface_r, mf_surface_r)
        if status_r != "MISMATCH":
            print(f"✗ Expected MISMATCH, got {status_r}")
            return 1
        print(f"  ⚠ Surface consistency: MISMATCH detected")
        print(f"    filename surface_priority = normal")
        print(f"    manifest surface_priority = urgent")
        print(f"  → triage fork recommended (spec §11)")
        print(f"    \"address visible, content sealed,")
        print(f"     mismatch is triage — not silent accept\"")

    # ─── Summary ───────────────────────────────────────────────
    print()
    print("═" * 64)
    print("  ✓ TIBET DROP COMPLETE")
    print("═" * 64)
    print(f"  transfer_pair_id:  {tpid_str(tpid)}")
    print(f"  payload_type:      ai_state")
    print(f"  bytes transferred: {len(bundle_bytes)} (pre-tunnel)")
    print(f"  tokens emitted:    transfer_out + transfer_in + tombstone (3)")
    print(f"  Lamport gen Bob:   {in_token['generation']} (max(10,42)+1)")
    print()
    print("  All five primitives validated:")
    print("    ✓ Ed25519 identity signing")
    print("    ✓ X25519 ECDH + HKDF tunnel-key derivation")
    print("    ✓ AES-256-GCM frame encryption with normative nonce rule")
    print("    ✓ TBZ-style bundle pack + verify (manifest_sig + block sigs)")
    print("    ✓ TIBET chain triple: transfer_out + transfer_in + tombstone")
    print()
    return 0
