# tibet-drop — TIBET Drop / TIBET TAT reference implementation

**Status:** v0.2.0 · 25 tests passing · demo end-to-end clean · used as
TBZ pack/verify substrate by `tibet-continuityd`

`tibet-drop` is the reference Python implementation of **TIBET Drop**
(product) / **TIBET TAT** (Touch-And-Transfer wire protocol) —
identity-bound device-to-device payload transfer with bilateral consent,
mutual causal anchoring (Lamport-style), and optional cryptographic
deactivation.

## What it does

```
TIBET Drop in one breath:
  • Two devices touch (NFC handshake — UPIP-seed exchange)
  • Both verify each other's identity (Ed25519, hardware-bound)
  • They agree to a tunnel-key (X25519 ECDH + HKDF-SHA256)
  • They open an AES-256-GCM tunnel (Wi-Fi Direct or BT LE)
  • Sender ships a .tza bundle (TBZ format with airdrop manifest)
  • Both sides write paired chain tokens (transfer_out + transfer_in)
  • Generation counter inherits Lamport-style: max(local, sender) + 1
  • Sender optionally tombstones (cryptographic deactivation)
  • All cryptographic, all auditable, no central server
```

The end-to-end demo (`tibet-drop demo`) walks through all nine steps of
the protocol and produces a clean validation pass for every primitive.

## What's new in v0.3.0

- **`detect_format(raw)`** — magic-byte dispatcher. Distinguishes
  `current` (`TBZ + 0x01 + BE-uint32 + CBOR`) from
  `legacy-tbz-packer` (`TBZ + 0x85 + walked-JSON`). Both formats
  can now be inspected; verify and unpack on legacy returns a
  clear error pointing at the repack workflow.
- **`canonical_filename(manifest)`** — reconstructs the canonical
  SSM filename from a manifest's surface fields. Means a peer can
  rename a bundle to anything human-readable
  (`vergadering-dinsdag.pdf`) and ANY receiver can recover the
  original SSM name from the manifest alone. Audit logs can record
  both the canonical and the operator-applied name, making rename
  events explicit instead of silent.
- Fallbacks for missing surface fields so the helper never crashes;
  operator gets a usable name even when the manifest is incomplete.

## What's new in v0.2.x

- `compare_surfaces()` and `parse_filename_surface()` exported from
  `tibet_drop.bundle` (= required by `tibet-continuityd` verify-stage
  for filename ↔ manifest mirroring)
- `pack` CLI gains `--surface-priority heartbeat` as 5e priority value
  (alongside `urgent / normal / background / sealed`); receivers that
  recognize the identity pin MAY route to a log-only lane
- `tibet-continuityd` v0.6.4+ depends on `tibet-drop>=0.2.0`

## Use cases

`tibet-drop` is a domain-agnostic transfer primitive. Wherever two
devices need to hand off identity, state, or credentials without a
central server, this protocol applies. Common deployments:

- **Autonomous vehicle / drone command verification** — off-grid
  freshness via mutual causal anchoring; no NTP dependency
- **Medical device handoff** — implant firmware update with
  provenance + family-recovery semantics
- **IoT device-to-device pairing** — Ed25519 hardware-bound identity,
  no cloud round-trip
- **Mobile-to-desktop state migration** — BYOS (Bring Your Own State)
  for password managers, AI assistants, custom workflows
- **Hardware authentication tokens** — security keys with
  cryptographic deactivation (tombstone) for revocation
- **Off-grid / disaster-resilient infrastructure** — Lamport-style
  causal time substrate, works without external time authority
- **W3C Verifiable Credentials peer transfer** — issuer-to-holder VC
  airdrop with bilateral consent, no centralised registry
- **AI agent state portability** — one application among many

The protocol does not assume AI. It assumes identity-bound hardware +
bilateral intent. Everything else is payload.

## Install

```bash
pip install tibet-drop
```

For development from source:

```bash
git clone https://github.com/Humotica/tibet-drop.git
cd tibet-drop
pip install -e .
```

## Quickstart

### Demo (end-to-end mock airdrop)

```bash
tibet-drop demo
```

Walks Alice → Bob through identity generation, handshake, tunnel
derivation, bundle pack, encrypted streaming, verification, and chain
token emission. ~10 seconds, no setup required.

### Full flow with subcommands

```bash
# 1. Both parties generate identities
tibet-drop init --aint alice.aint --out ./alice
tibet-drop init --aint bob.aint --out ./bob

# 2. Sender generates a UPIP-seed (mock NFC handshake)
tibet-drop handshake --identity ./alice --output alice.seed \
    --payload-type ai_state --wipe

# 3. Inspect the seed (decode + verify signature)
tibet-drop seed-inspect alice.seed

# 4. Pack a payload directory into a .tza bundle
BOB_PUBKEY=$(python3 -c "import json;print(json.load(open('./bob/identity.json'))['pubkey_hex'])")
tibet-drop pack \
    --identity ./alice \
    --receiver-aint bob.aint \
    --receiver-pubkey $BOB_PUBKEY \
    --input ./alice-state-dir \
    --output airdrop.tza \
    --payload-type ai_state

# 5. Verify and inspect the bundle
tibet-drop verify airdrop.tza
tibet-drop inspect airdrop.tza

# 6. Unpack on the receiver side
tibet-drop unpack airdrop.tza --out ./bob-restored
```

## Architecture

```
src/tibet_drop/
   crypto.py       Ed25519 identity, X25519 ephemeral, HKDF, AES-256-GCM
   handshake.py    UPIP-seed encode/decode/verify (CBOR, ≤512 bytes)
   tokens.py       transfer_out / transfer_in / tombstone TIBET tokens
   bundle.py       .tza pack/verify/inspect (TBZ-compatible manifest)
   verifier.py     stateful verifier — ReplayStore, VerificationState,
                    ChunkSequenceGate, post-tombstone rejection
   demo.py         End-to-end mock airdrop demonstration
   cli.py          tibet-drop subcommands (argparse)
```

## Protocol Specification: TIBET TAT (Phase 0)

The wire protocol is fully specified at v1. Nine steps:

```
TIME    SENDER                          RECEIVER
─────  ──────────────────────────       ──────────────────────────
T0      User taps "TIBET Drop"
        Generate ephemeral X25519 key
        Generate transfer_pair_id (UUID v7)
T1      NFC bump (or QR fallback v0.2+)
T2      ─── seed_send (CBOR, ~250b) →   Verify sig + .aint claim
                                         Show consent UI
T3      ◄─── seed_recv (consent=accept) User accepts
T4      Verify consent + tpid
        ECDH(eph_priv, peer_eph_pub) → shared_secret
        HKDF → tunnel_key + nonce_prefix
T5      WRITE transfer_out token (chain-anchored)
T6      Open Wi-Fi Direct tunnel
T7      Stream chunks: AES-256-GCM      Decrypt + verify per chunk
        nonce = nonce_prefix(8) ||
                u32_be(chunk_index)(4)
T8      Final chunk: content_sha256     Verify match with sender's
                                         transfer_out.payload_summary
T9                                        WRITE transfer_in token
                                          (gen = max(local, sender) + 1)
T10     Tunnel close, ephemeral keys     Tunnel close, ephemeral keys
        purged                            purged
T11     Optional: WRITE tombstone        State materialised
        (cryptographic deactivation)
```

### Cryptographic primitives (NORMATIVE)

| Layer | Algorithm | Purpose |
|---|---|---|
| Identity | Ed25519 (RFC 8032) | Long-lived hardware-bound key per device |
| Ephemeral | X25519 (RFC 7748) | Per-airdrop ephemeral key for ECDH (forward secrecy) |
| KDF | HKDF-SHA256 (RFC 5869) | Tunnel key + nonce-prefix derivation |
| Tunnel | AES-256-GCM (RFC 5116) | Per-chunk authenticated encryption |
| Hashing | SHA-256 (FIPS 180-4) | Content hashes, fingerprints |
| Encoding | CBOR (RFC 8949) | Canonical seed encoding |

### AES-GCM nonce rule (NORMATIVE)

```
nonce_prefix    8 bytes  (HKDF-derived per session)
chunk_index    4 bytes  (u32 big-endian, monotonic from 0)

nonce = nonce_prefix || u32_be(chunk_index)   # 12 bytes total
```

Sender and receiver MUST derive the identical nonce for chunk N from
identical (nonce_prefix, N). Replay detection at receiver: track
expected_next_chunk_index, reject decreasing or duplicate.

### Token schemas

Three TIBET token types, all Ed25519-signed over canonical-JSON form:

- `transfer_out` — sender chain entry; carries tpid, receiver fp,
  payload summary, ephemeral pubkey
- `transfer_in` — receiver chain entry; carries same tpid, sender
  reference, generation = max(local, sender) + 1 (Lamport rule)
- `tombstone_token` — optional terminal-state attestation; carries
  recovery_policy (`destroyed`, `restorable_via_successor`,
  `restorable_via_root_authority`)

### Identity model

v0.1 supports single Ed25519 key per identity. v0.2+ will add the
multi-device delegation model documented in the spec (root + delegated
keys, X.509-style chain-of-delegation, revocation certificates).

### Bundle format (.tza)

`.tza` archives are TBZ v1 compatible — readable by `tibet-zip-cli`
for basic integrity checks. Airdrop-specific manifest fields are
additive, not breaking.

## What v0.1 does NOT do (yet)

- **Real NFC** — handshake is mock-via-file (CBOR encoded, sigs valid)
- **Real Wi-Fi Direct** — tunnel is mock-in-memory chunked AES-256-GCM
- **Multi-device delegation** — single Ed25519 key per identity (v0.2)
- **SEMA-context headers** — semantic frame negotiation (post-MVP)
- **Drift-record** — pairwise drift declaration (post-MVP)
- **CLI verifier integration** — stateful verifier-laag is in
  `verifier.py` but not yet plumbed through `cli.py` verify/demo flows

These are well-scoped extensions for v0.2 / v0.3.

## Testing

```bash
PYTHONPATH=src python3 -m pytest tests/
```

Two suites, 25 tests total:

- `tests/test_adversarial.py` (15) — bundle tamper, truncation, swap,
  replay, malformed seeds, oversized seeds, wrong sigs, AES/AAD/key
  tamper, generation rule, token sig
- `tests/test_verifier.py` (10) — ReplayStore persistence, transfer-pair
  matching, asymmetry detection, tombstone-aware rejection, chunk
  sequence continuity

The demo (`tibet-drop demo`) serves as both end-to-end test and live
documentation.

## Prior Art & Standards

`tibet-drop` is part of the **TIBET protocol family** — an Ed25519-signed,
hash-linked audit chain published as IETF Internet-Draft on
**24 January 2026**.

Architectural concepts (FIR/A trust state machine, Lamport-style causal
time substrate, hardware-bound Ed25519 identity, transfer-pair mutual
anchoring, tombstone-token cryptographic deactivation, generation-counter
inheritance) originate in design sessions **November–December 2025**,
formalised in `aether-founding-spec`, and standardised through these
IETF drafts:

- `draft-vandemeent-jis-identity-00` — Joint Identity Service
- `draft-vandemeent-tibet-provenance-00` — Audit chain primitive
- `draft-vandemeent-ains-discovery-00` — Decentralised resolver
- `draft-vandemeent-rvp-continuous-verification-00` — Continuous verification
- `draft-vandemeent-upip-process-integrity-00` — Process integrity

Empirical validation: Joint case study with Red Specter Security
Research (RS-2026-001, May 2026) demonstrates chain enforcement under
NATO-grade adversarial pressure.

**Timestamps for prior-art reference:**

- Design origin: November–December 2025 (`aether-founding-spec`)
- IETF drafts published: 24 January 2026
- First PyPI release of `tibet-drop`: 8 May 2026
- First public GitHub release: 8 May 2026

The Lamport-style logical time semantic (causal ordering as primary,
wall-clock as auxiliary) draws on Leslie Lamport's foundational work
*Time, Clocks, and the Ordering of Events in a Distributed System*
(Communications of the ACM, 1978). The transfer-pair primitive
extends this with cryptographic mutual anchoring between two
independent chains.

MIT licensed to encourage adoption while preserving attribution. Forks
welcome. Patent claims discouraged (defensive posture via Open
Invention Network membership).

## Compatibility with TIBET ecosystem

- `.tza` bundles are TBZ v1 compatible — readable by `tibet-zip-cli`
  for basic integrity checks
- TIBET tokens use the canonical-form-then-sign discipline shared
  across the HumoticaOS substrate
- `tibet-bom` (PyPI) can ingest `transfer_out` / `transfer_in` /
  `tombstone` tokens via `collect json` for incident-transparency
  reports

## License

MIT — see LICENSE.

## Author

Jasper van de Meent · Humotica · <info@humotica.com>
