"""Tests for Semantic Surface Manifest implementation.

Per phase-0-tza-bundle-format §2.2 + spec §11:
- pack_bundle accepts surface_* fields and writes them to manifest
- parse_filename_surface extracts fields from <date>.<context>.<profile>.<priority> form
- compare_surfaces returns MATCH / MISMATCH / PARTIAL / NONE per RULE 6
- mismatch is detected after rename without altering sealed bundle
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from tibet_drop.bundle import (
    compare_surfaces,
    inspect_bundle,
    pack_bundle,
    parse_filename_surface,
    verify_bundle,
)
from tibet_drop.crypto import IdentityKey
from tibet_drop.handshake import new_tpid


# ─── parse_filename_surface ─────────────────────────────────────


def test_parse_filename_surface_canonical():
    s = parse_filename_surface("2026-05-09.demo.claude.urgent.tza")
    assert s == {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "demo",
        "surface_profile": "claude",
        "surface_priority": "urgent",
    }


def test_parse_filename_surface_no_tza_suffix():
    s = parse_filename_surface("2026-05-09.demo.claude.urgent")
    assert s is not None
    assert s["surface_priority"] == "urgent"


def test_parse_filename_surface_too_few_segments():
    assert parse_filename_surface("foo.tza") is None
    assert parse_filename_surface("foo.bar.baz.tza") is None


def test_parse_filename_surface_invalid_chars_rejected():
    # Underscore not allowed in v1
    assert parse_filename_surface("2026-05-09.foo_bar.claude.urgent.tza") is None
    # Uppercase not allowed in v1
    assert parse_filename_surface("2026-05-09.demo.Claude.urgent.tza") is None


# ─── compare_surfaces ────────────────────────────────────────────


def test_compare_match():
    fn = {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "demo",
        "surface_profile": "claude",
        "surface_priority": "urgent",
    }
    assert compare_surfaces(fn, fn.copy()) == "MATCH"


def test_compare_mismatch():
    fn = {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "demo",
        "surface_profile": "claude",
        "surface_priority": "urgent",
    }
    mf = fn.copy()
    mf["surface_priority"] = "normal"
    assert compare_surfaces(fn, mf) == "MISMATCH"


def test_compare_partial():
    fn = {
        "surface_time_fragment": "2026-05-09",
        "surface_context": "demo",
        "surface_profile": "claude",
        "surface_priority": "urgent",
    }
    assert compare_surfaces(fn, None) == "PARTIAL"
    assert compare_surfaces(None, fn) == "PARTIAL"


def test_compare_none():
    assert compare_surfaces(None, None) == "NONE"


# ─── End-to-end pack + verify ────────────────────────────────────


@pytest.fixture
def alice_bob():
    alice = IdentityKey.generate()
    bob = IdentityKey.generate()
    return alice, bob


def _pack_demo(tmp: Path, alice: IdentityKey, bob: IdentityKey,
                outname: str, **surface_kwargs) -> Path:
    src = tmp / "state"
    src.mkdir()
    (src / "persona.json").write_text('{"persona": "Alice"}')
    blocks = [(p.name, p.read_bytes()) for p in src.iterdir()]

    out = tmp / outname
    pack_bundle(
        output_path=out,
        blocks=blocks,
        sender_aint="alice.aint",
        sender_signer=alice,
        receiver_aint="bob.aint",
        receiver_pubkey_hex=bob.pub_bytes().hex(),
        payload_type="ai_state",
        tpid=new_tpid(),
        **surface_kwargs,
    )
    return out


def test_pack_emits_surface_fields(alice_bob):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        out = _pack_demo(
            tmp, alice, bob,
            outname="2026-05-09.demo.claude.urgent.tza",
            surface_time_fragment="2026-05-09",
            surface_context="demo",
            surface_profile="claude",
            surface_priority="urgent",
        )
        manifest = inspect_bundle(out)
        assert manifest["surface_time_fragment"] == "2026-05-09"
        assert manifest["surface_context"] == "demo"
        assert manifest["surface_profile"] == "claude"
        assert manifest["surface_priority"] == "urgent"


def test_pack_omits_surface_when_not_given(alice_bob):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        out = _pack_demo(tmp, alice, bob, outname="legacy.tza")
        manifest = inspect_bundle(out)
        assert "surface_time_fragment" not in manifest
        assert "surface_profile" not in manifest


def test_verify_with_matching_surface(alice_bob):
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        out = _pack_demo(
            tmp, alice, bob,
            outname="2026-05-09.demo.claude.urgent.tza",
            surface_time_fragment="2026-05-09",
            surface_context="demo",
            surface_profile="claude",
            surface_priority="urgent",
        )
        valid, manifest, errors = verify_bundle(out)
        assert valid, f"unexpected errors: {errors}"

        fn_surface = parse_filename_surface(out.name)
        mf_surface = {k: manifest[k] for k in (
            "surface_time_fragment", "surface_context",
            "surface_profile", "surface_priority")}
        assert compare_surfaces(fn_surface, mf_surface) == "MATCH"


def test_verify_detects_mismatch_after_rename(alice_bob):
    """Rename test: sealed bundle stays valid, surface mismatch detected."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        out = _pack_demo(
            tmp, alice, bob,
            outname="2026-05-09.demo.claude.urgent.tza",
            surface_time_fragment="2026-05-09",
            surface_context="demo",
            surface_profile="claude",
            surface_priority="urgent",
        )
        # Rename: priority urgent → normal
        renamed = tmp / "2026-05-09.demo.claude.normal.tza"
        out.rename(renamed)

        # Sealed bundle still valid (cryptographic integrity intact)
        valid, manifest, errors = verify_bundle(renamed)
        assert valid, "sealed bundle should remain cryptographically valid"

        # But surface comparison shows mismatch
        fn_surface = parse_filename_surface(renamed.name)
        mf_surface = {k: manifest[k] for k in (
            "surface_time_fragment", "surface_context",
            "surface_profile", "surface_priority")}
        assert compare_surfaces(fn_surface, mf_surface) == "MISMATCH"


def test_verify_legacy_bundle_no_surface(alice_bob):
    """Bundle without surface_* fields: NONE status, no error."""
    alice, bob = alice_bob
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        out = _pack_demo(tmp, alice, bob, outname="legacy.tza")
        valid, manifest, errors = verify_bundle(out)
        assert valid

        fn_surface = parse_filename_surface(out.name)
        mf_surface = None  # no surface_* in manifest
        assert compare_surfaces(fn_surface, mf_surface) == "NONE"
