# Changelog

## 0.3.4

- **`TIBET_DROP_TIMEOUT` env override for HTTP transport.** The `send`/`recv` hub
  calls used a hard-coded 15 s socket timeout, which is too short to finish the
  *upload write* of a large sealed carrier (tens of MB) — the write times out with
  `HTTP 0 / write operation timed out`. The timeout is now read from
  `TIBET_DROP_TIMEOUT` (seconds), defaulting to `15` when unset. Send a big `.tza`
  with e.g. `TIBET_DROP_TIMEOUT=600 tibet-drop send bundle.tza --to peer.aint --brein`.
  Discovered dogfooding a 24 MB review-bundle drop; download (`recv`) is unaffected
  in practice because downlink is typically far wider than uplink.

## 0.3.3

- `detect_format` accepts `str`/`Path` in addition to `bytes` (Richard #1 caveat fix).

## 0.3.0

- Dual-format verifier + canonical_filename helper.

## 0.2.1

- Export `compare_surfaces` + `parse_filename_surface`; heartbeat dispatch priority.

## 0.1.0

- Initial public release.
