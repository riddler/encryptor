# Architecture Decision Records

| # | Decision | Status |
|---|---|---|
| [0001](0001-vault-layer.md) | A vault is a supervised, host-owned module that wraps the engine completely | accepted (2026-08-27) |
| [0002](0002-key-providers.md) | A key provider resolves a selector to key descriptors, and the vault alone builds keyrings | accepted (2026-08-27) |
| [0003](0003-per-tenant-envelope.md) | A tenant key is a random key wrapped into an ordinary message, and the host stores the wrapping | accepted (2026-08-27, amended) |
| [0004](0004-encryption-context.md) | The encryption context is a vault-composed, profile-enforced set of identifying keys | accepted (2026-08-27, amended) |
| [0005](0005-rotation-and-crypto-shred.md) | Rotation is three independent lifecycles, and only the shred is irreversible | accepted (2026-08-27) |
| [0006](0006-telemetry-and-observability.md) | Telemetry is a closed event set whose metadata is an allow-list, and nothing key-shaped is ever in it | proposed (2026-08-27) |

New ADRs: next number, same three-section format (Context, Decision,
Consequences), plus typespecs, at least one worked example, and any open
questions the record could not settle. Pick the number against a freshly
fetched remote.

This repository inherits the family's ADR practice rather than restating it,
so there is no local "record architecture decisions" record. A bare
`ADR-NNNN` cites this repository's own records; a cross-repo citation carries
the owning repository's beads prefix (`enc-ADR-0001` is this repository's
ADR-0001 seen from elsewhere, `st-ADR-0052` is statifier-ex's ADR-0052).

The encryption engine is `aws_encryption_sdk`. Where a record cites its
behaviour, the citation is against the published v1.0.0 source, not its
guides, and the module path is given so the claim can be re-checked.
