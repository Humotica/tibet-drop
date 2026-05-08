from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import cbor2
import pytest

from tibet_drop.bundle import pack_bundle, verify_bundle
from tibet_drop.crypto import (
    EphemeralKey,
    IdentityKey,
    decrypt_chunk,
    derive_tunnel_keys,
    encrypt_chunk,
)
from tibet_drop.handshake import RecvSeed, SendSeed, new_tpid, verify_seed
from tibet_drop.tokens import TombstoneToken, TransferInToken, TransferOutToken, verify_token


def _bundle_fixture(tmp_path: Path) -> tuple[Path, dict, IdentityKey, bytes]:
    sender = IdentityKey.generate()
    receiver = IdentityKey.generate()
    tpid = new_tpid()
    bundle_path = tmp_path / "test.tza"
    manifest = pack_bundle(
        output_path=bundle_path,
        blocks=[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
        ],
        sender_aint="alice.aint",
        sender_signer=sender,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=receiver.pub_bytes().hex(),
        payload_type="ai_state",
        tpid=tpid,
        transfer_out_token_id="tok-1",
    )
    return bundle_path, manifest, sender, tpid


def test_seed_malformed_cbor_fails_gracefully() -> None:
    valid, body, err = verify_seed(b"\xa1\x01")
    assert not valid
    assert body == {}
    assert err and "CBOR decode failed" in err


def test_seed_wrong_signature_rejected() -> None:
    alice = IdentityKey.generate()
    eph = EphemeralKey.generate()
    seed = SendSeed(
        aint="alice.aint",
        pk_from=alice.pub_bytes(),
        epk_from=eph.pub_bytes(),
        tpid=new_tpid(),
        intent={"payload": "ai_state", "size": 1, "wipe": False},
    )
    blob = bytearray(seed.encode(alice))
    blob[-1] ^= 0x01
    valid, _, err = verify_seed(bytes(blob))
    assert not valid
    assert err == "Signature verification failed"


def test_seed_oversize_rejected() -> None:
    alice = IdentityKey.generate()
    eph = EphemeralKey.generate()
    seed = SendSeed(
        aint="alice.aint",
        pk_from=alice.pub_bytes(),
        epk_from=eph.pub_bytes(),
        tpid=new_tpid(),
        intent={"payload": "ai_state", "size": 1, "wipe": False, "padding": "x" * 700},
    )
    blob = seed.encode(alice)
    valid, _, err = verify_seed(blob)
    assert not valid
    assert err and "Seed exceeds hard limit" in err


def test_seed_unsupported_kind_rejected() -> None:
    alice = IdentityKey.generate()
    eph = EphemeralKey.generate()
    seed = SendSeed(
        aint="alice.aint",
        pk_from=alice.pub_bytes(),
        epk_from=eph.pub_bytes(),
        tpid=new_tpid(),
        intent={"payload": "ai_state", "size": 1, "wipe": False},
    )
    body = seed.to_canonical_no_sig()
    body["kind"] = "weird_kind"
    canonical = cbor2.dumps(body, canonical=True)
    body["sig"] = alice.sign(canonical)
    valid, _, err = verify_seed(cbor2.dumps(body, canonical=True))
    assert not valid
    assert err == "Unsupported kind: 'weird_kind'"


def test_receiver_seed_tpid_mismatch_detectable() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    alice_eph = EphemeralKey.generate()
    bob_eph = EphemeralKey.generate()
    send = SendSeed(
        aint="alice.aint",
        pk_from=alice.pub_bytes(),
        epk_from=alice_eph.pub_bytes(),
        tpid=new_tpid(),
        intent={"payload": "ai_state", "size": 1, "wipe": False},
    )
    recv = RecvSeed(
        aint="bob.aint",
        pk_from=bob.pub_bytes(),
        epk_from=bob_eph.pub_bytes(),
        tpid=new_tpid(),
        consent="accept",
    )
    send_valid, send_body, _ = verify_seed(send.encode(alice))
    recv_valid, recv_body, _ = verify_seed(recv.encode(bob))
    assert send_valid and recv_valid
    assert send_body["tpid"] != recv_body["tpid"]


def test_bundle_tampered_block_detected(tmp_path: Path) -> None:
    bundle_path, _, _, _ = _bundle_fixture(tmp_path)
    raw = bytearray(bundle_path.read_bytes())
    raw[-1] ^= 0x01
    tampered = tmp_path / "tampered.tza"
    tampered.write_bytes(bytes(raw))
    valid, _, errors = verify_bundle(tampered)
    assert not valid
    assert any("hash mismatch" in error for error in errors)


def test_bundle_truncated_detected(tmp_path: Path) -> None:
    bundle_path, _, _, _ = _bundle_fixture(tmp_path)
    truncated = tmp_path / "truncated.tza"
    raw = bundle_path.read_bytes()
    truncated.write_bytes(raw[:-3])
    valid, _, errors = verify_bundle(truncated)
    assert not valid
    assert any("truncated bundle" in error or "hash mismatch" in error for error in errors)


def test_bundle_swapped_block_order_detected(tmp_path: Path) -> None:
    bundle_path, manifest, _, _ = _bundle_fixture(tmp_path)
    raw = bundle_path.read_bytes()
    pos = 0
    _total = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4
    mlen = struct.unpack(">I", raw[pos:pos + 4])[0]
    pos += 4 + mlen
    b1_len = struct.unpack(">I", raw[pos:pos + 4])[0]
    b1_hdr = raw[pos:pos + 4]
    pos += 4
    b1 = raw[pos:pos + b1_len]
    pos += b1_len
    b2_len = struct.unpack(">I", raw[pos:pos + 4])[0]
    b2_hdr = raw[pos:pos + 4]
    pos += 4
    b2 = raw[pos:pos + b2_len]

    swapped = raw[: 8 + mlen] + b2_hdr + b2 + b1_hdr + b1
    swapped_path = tmp_path / "swapped.tza"
    swapped_path.write_bytes(swapped)
    valid, checked_manifest, errors = verify_bundle(swapped_path)
    assert checked_manifest["tpid"] == manifest["tpid"]
    assert not valid
    assert any("hash mismatch" in error for error in errors)


def test_bundle_replay_tpid_rejected(tmp_path: Path) -> None:
    bundle_path, manifest, _, _ = _bundle_fixture(tmp_path)
    valid, _, errors = verify_bundle(bundle_path, seen_tpids={manifest["tpid"]})
    assert not valid
    assert any("replayed tpid detected" in error for error in errors)


def test_bundle_tiny_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "tiny.tza"
    path.write_bytes(b"x")
    valid, _, errors = verify_bundle(path)
    assert not valid
    assert errors == ["File too small to be a valid .tza"]


def test_chunk_index_gap_rejected_by_crypto() -> None:
    alice_eph = EphemeralKey.generate()
    bob_eph = EphemeralKey.generate()
    tpid = new_tpid()
    alice_key, alice_np = derive_tunnel_keys(alice_eph, bob_eph.pub_bytes(), tpid)
    bob_key, bob_np = derive_tunnel_keys(bob_eph, alice_eph.pub_bytes(), tpid)
    aad_gap = tpid + struct.pack(">I", 2) + struct.pack(">I", 4)
    ct = encrypt_chunk(alice_key, alice_np, 2, b"payload", aad_gap)
    wrong_aad = tpid + struct.pack(">I", 3) + struct.pack(">I", 4)
    with pytest.raises(Exception):
        decrypt_chunk(bob_key, bob_np, 3, ct, wrong_aad)


def test_wrong_aad_or_tunnel_key_detected() -> None:
    alice_eph = EphemeralKey.generate()
    bob_eph = EphemeralKey.generate()
    tpid = new_tpid()
    alice_key, alice_np = derive_tunnel_keys(alice_eph, bob_eph.pub_bytes(), tpid)
    bob_key, bob_np = derive_tunnel_keys(bob_eph, alice_eph.pub_bytes(), tpid)
    aad = tpid + struct.pack(">I", 0) + struct.pack(">I", 1)
    ct = encrypt_chunk(alice_key, alice_np, 0, b"payload", aad)
    with pytest.raises(Exception):
        decrypt_chunk(bob_key, bob_np, 0, ct, tpid + struct.pack(">I", 0) + struct.pack(">I", 2))
    tampered_key = bytes([bob_key[0] ^ 0x01]) + bob_key[1:]
    with pytest.raises(Exception):
        decrypt_chunk(tampered_key, bob_np, 0, ct, aad)


def test_generation_inheritance_rule_holds() -> None:
    bob = IdentityKey.generate()
    alice = IdentityKey.generate()
    token = TransferInToken(
        actor_aint="bob.aint",
        actor_pubkey=bob.pub_bytes(),
        sender_aint="alice.aint",
        sender_fp=alice.fingerprint(),
        payload_type="ai_state",
        payload_received={"ok": True},
        transfer_pair_id=new_tpid(),
        sender_generation=42,
        local_generation=10,
        sender_transfer_out_token_id="tok-1",
    )
    assert token.generation == 43


def test_token_signature_mismatch_rejected() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    token = TransferOutToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        receiver_aint="bob.aint",
        receiver_fp=bob.fingerprint(),
        payload_type="ai_state",
        payload_summary={"size_bytes": 1},
        transfer_pair_id=new_tpid(),
        generation=1,
    ).to_dict(alice)
    token["actor_pubkey"] = bob.pub_bytes().hex()
    valid, err = verify_token(token)
    assert not valid
    assert err == "Signature verification failed"


def test_tombstone_token_signature_validates() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    tomb = TombstoneToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        transfer_out_ref="tok-1",
        successor_aint="bob.aint",
        successor_fp=bob.fingerprint(),
        generation=7,
    ).to_dict(alice)
    valid, err = verify_token(tomb)
    assert valid
    assert err is None
