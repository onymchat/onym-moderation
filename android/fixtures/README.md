# Android wire-contract fixtures

These fixtures are the **normative** cross-language contract for the
Google device-recall profile
(`onym:moderation-enforcement-profile:google-device-recall-v1`). The
direction of authority is the reverse of the iOS profile: no Android
client existed when this profile was implemented, so the backend
(`src/payload.rs`) generates these values, and the Kotlin client's
`SignedSessionPayload` must reproduce them byte-for-byte
(Moderation-Device-Recall.md §8 gap 11 requires publication before
implementation).

Regenerate only from `src/payload.rs` — never by hand — and version the
context strings if the layout ever changes.

## Payload layout

For each field in order — context, challenge (raw bytes), user key,
RFC 3339 UTC timestamp, mandate ref (empty when absent) — a big-endian
`u32` length prefix followed by the raw bytes.

- The identity signature (Ed25519, the user's Stellar-derived key,
  `onym:key:<hex>`) is over exactly these bytes.
- Play Integrity's `requestHash` is `base64url-nopad(SHA-256(payload))`.
- The integrity token is **not** a payload field: it does not exist
  until after the hash is computed. It binds to the payload through the
  echoed `requestHash`.

Contexts:

- enroll: `onym-moderation-android-enroll-v1`
- gate-check: `onym-moderation-android-gate-v1`

See `payload-fixtures.json` for the frozen vectors; the same values are
pinned by `src/payload.rs`'s `*_fixture_is_frozen` tests.
