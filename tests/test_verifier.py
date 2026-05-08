from __future__ import annotations

from pathlib import Path

from tibet_drop.crypto import IdentityKey
from tibet_drop.handshake import new_tpid
from tibet_drop.tokens import TombstoneToken, TransferInToken, TransferOutToken
from tibet_drop.verifier import (
    ChunkSequenceGate,
    ReplayStore,
    VerificationState,
    reject_if_post_tombstone,
    verify_tombstone_token,
    verify_transfer_in_token,
    verify_transfer_out_token,
)


def _transfer_out(alice: IdentityKey, bob: IdentityKey, tpid: bytes, generation: int = 42) -> dict:
    return TransferOutToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        receiver_aint="bob.aint",
        receiver_fp=bob.fingerprint(),
        payload_type="ai_state",
        payload_summary={"size_bytes": 123},
        transfer_pair_id=tpid,
        generation=generation,
    ).to_dict(alice)


def _transfer_in(
    bob: IdentityKey,
    alice: IdentityKey,
    tpid: bytes,
    sender_transfer_out_token_id: str,
    sender_generation: int = 42,
    local_generation: int = 10,
) -> dict:
    return TransferInToken(
        actor_aint="bob.aint",
        actor_pubkey=bob.pub_bytes(),
        sender_aint="alice.aint",
        sender_fp=alice.fingerprint(),
        payload_type="ai_state",
        payload_received={"size_bytes": 123},
        transfer_pair_id=tpid,
        sender_generation=sender_generation,
        local_generation=local_generation,
        sender_transfer_out_token_id=sender_transfer_out_token_id,
    ).to_dict(bob)


def test_replay_store_persists_seen_tpids(tmp_path: Path) -> None:
    store = ReplayStore(tmp_path / "seen.json")
    tpid = "abc-123"
    assert not store.contains(tpid)
    store.remember(tpid)
    assert store.contains(tpid)


def test_verify_transfer_out_registers_replay_and_state(tmp_path: Path) -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    tpid = new_tpid()
    token = _transfer_out(alice, bob, tpid)
    store = ReplayStore(tmp_path / "seen.json")
    state = VerificationState()

    valid, err = verify_transfer_out_token(token, replay_store=store, state=state)
    assert valid and err is None

    valid2, err2 = verify_transfer_out_token(token, replay_store=store, state=state)
    assert not valid2
    assert "Replay detected" in str(err2)


def test_transfer_in_without_matching_out_rejected() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    token = _transfer_in(bob, alice, new_tpid(), sender_transfer_out_token_id="tok-missing")
    valid, err = verify_transfer_in_token(token, state=VerificationState())
    assert not valid
    assert "Asymmetry detected" in str(err)


def test_transfer_in_with_matching_out_accepted() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    tpid = new_tpid()
    out_token = _transfer_out(alice, bob, tpid)
    in_token = _transfer_in(
        bob,
        alice,
        tpid,
        sender_transfer_out_token_id=out_token["token_id"],
    )
    state = VerificationState()
    verify_transfer_out_token(out_token, state=state)
    valid, err = verify_transfer_in_token(in_token, state=state)
    assert valid and err is None


def test_transfer_in_wrong_sender_chain_ref_rejected() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    tpid = new_tpid()
    out_token = _transfer_out(alice, bob, tpid)
    in_token = _transfer_in(bob, alice, tpid, sender_transfer_out_token_id="wrong-id")
    valid, err = verify_transfer_in_token(in_token, matching_transfer_out=out_token)
    assert not valid
    assert "sender_chain_ref.transfer_out_token_id mismatch" == err


def test_tombstone_registration_and_post_tombstone_rejection() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    state = VerificationState()
    tomb = TombstoneToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        transfer_out_ref="tok-1",
        successor_aint="bob.aint",
        successor_fp=bob.fingerprint(),
        generation=43,
        recovery_policy="destroyed",
    ).to_dict(alice)
    valid, err = verify_tombstone_token(tomb, state=state)
    assert valid and err is None

    later = _transfer_out(alice, bob, new_tpid(), generation=44)
    later["created_at"] = "9999-01-01T00:00:00Z"
    allowed, reason = reject_if_post_tombstone(later, state)
    assert not allowed
    assert "Post-tombstone token rejected" in str(reason)


def test_pre_tombstone_token_not_rejected() -> None:
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    state = VerificationState()
    tomb = TombstoneToken(
        actor_aint="alice.aint",
        actor_pubkey=alice.pub_bytes(),
        transfer_out_ref="tok-1",
        successor_aint="bob.aint",
        successor_fp=bob.fingerprint(),
        generation=43,
    ).to_dict(alice)
    tomb["created_at"] = "2026-05-08T12:00:00Z"
    verify_tombstone_token(tomb, state=state)

    earlier = _transfer_out(alice, bob, new_tpid(), generation=40)
    earlier["created_at"] = "2026-05-08T11:59:59Z"
    allowed, reason = reject_if_post_tombstone(earlier, state)
    assert allowed
    assert reason is None


def test_chunk_sequence_gate_accepts_strict_sequence() -> None:
    gate = ChunkSequenceGate()
    assert gate.accept(0) == (True, None)
    assert gate.accept(1) == (True, None)
    assert gate.accept(2) == (True, None)


def test_chunk_sequence_gate_rejects_gap() -> None:
    gate = ChunkSequenceGate()
    gate.accept(0)
    ok, err = gate.accept(2)
    assert not ok
    assert err == "chunk index gap: expected 1 got 2"


def test_chunk_sequence_gate_rejects_decrease() -> None:
    gate = ChunkSequenceGate()
    gate.accept(0)
    gate.accept(1)
    ok, err = gate.accept(1)
    assert not ok
    assert err == "chunk index decreased: expected 2 got 1"
