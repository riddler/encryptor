# Adversarial review ledger, 2026-10-06

This ledger lists, by number, what an adversarial reading of this package found
and what was done about each finding. It is a dated record, like the notes in
`docs/measurements/`. It is not a page to learn from, and it is not a decision
record. [The threat model](../explanation/threat-model.md) states the claims
these findings were tested against.

**Self-reviewed, no formal third-party audit.** Two reviewers read the code.
The first is an LLM adversarial pass with fresh context, described below. The
second is the maintainer, who is the team's security lead. Nobody outside the
project reviewed it. This is not an independent engineer's review, and nothing
here says the package is audited, certified or verified secure.

## Scope and method

The LLM pass read encryptor at commit
[`aac183b`](https://github.com/riddler/encryptor/tree/aac183b92c4b502bc4eb78397d6025ddbdda28d4).
The other findings come from the vector, interop and SP 800-38D work that
produced the threat model, and from two earlier review reads. Each entry names
the commit it was found at, and the engine's entries name the
`aws_encryption_sdk` commit that encryptor's `mix.lock` resolved: version
1.0.0, at
[`a84686d`](https://github.com/riddler/aws-encryption-sdk-elixir/tree/a84686db4be53043ba14a6d1bbacba984274fe22).
A `file:line` is at that entry's commit, so the line numbers may have moved on
`main` since.

Each entry carries:

- an id, F1 onward;
- where: the file and lines at the named commit, and the function;
- who found it: the LLM pass, the maintainer, or the test or CI job that showed
  it;
- a severity on the scale below;
- the claim it breaks, quoted from a public page, a moduledoc or a code comment;
- a disposition, which is one of:
  - **FIXED** in a named pull request, with the test that pins the fix and
    that test's sabotage note (the mutation that turns it red). A finding
    FIXED by documentation is one where the documentation now states what
    the code does, and a test pins that behaviour;
  - **ACCEPTED**, with the maintainer's reason;
  - **DEFERRED** to a named bead in this repository's tracker, or in
    encryptor_ecto's where the entry says so;
  - **FIX IN PROGRESS** in a named pull request that is not merged yet;
  - **PENDING** the maintainer's disposition.

### The severity scale

- **Critical**: plaintext or key disclosure, or an authentication bypass.
- **High**: a guarantee the documentation states does not hold.
- **Medium**: a weakness that matters only with an unusual configuration or a
  second failure, or a documented guarantee that holds only partly.
- **Low/Info**: hardening, clarity, or a missing test for a claim that does
  hold.

### What a finding holds

A Critical or High finding must be FIXED, or carry the maintainer's ACCEPTED
disposition, before any release prep merges. A Medium or lower finding may ship
DEFERRED to a named bead.

## The LLM pass

One LLM reviewer ran the pass, with no context from the work that wrote the
code or the threat model. The model was `claude-opus-5-5`, and the pass ran on
2026-10-06. Its prompt is kept verbatim in the project's private working
records. In substance it said this:

- **Scope.** encryptor at a fixed commit of `main` (`aac183b`). The inputs were
  the threat model and the security model, every file under `lib/`, and the
  accepted decision records the code or the threat model cites. The tests were
  read only to check whether a claim is pinned. The engine, at the version
  `mix.lock` resolves, was read only where a claim depends on it.
- **Method.** For each claim in the threat model and each security-relevant
  function in `lib/`, try to break it. The prompt named these attacks: wrong or
  missing context; one record's ciphertext substituted for another's; cold,
  warm and poisoned cache states; rotation and shred edge cases; malformed or
  truncated ciphertext; secrets leaking through error messages, logs, telemetry
  or exceptions; timing; configuration a host can get wrong without being
  refused; concurrency; and anything the documentation promises that the code
  does not enforce. A concrete reproduction was preferred to an argument, and
  the reviewer said which findings it reproduced.
- **Severity.** The scale above, in those words.
- **Rules.** Read-only. Every file the reviewer wrote was scratch and was
  deleted before it returned. A test run held a machine slot. No secret value
  was read, printed or passed.
- **Return.** The commit reviewed, and for each finding: its severity, where it
  is, the claim it breaks, whether it was reproduced or reasoned, and a
  suggested disposition. Then the claims it attacked and could not break.

Its findings are F7 to F16 below.

These are the claims it attacked and could not break, at `aac183b`. One line
each, as it reported them:

- The context comparison above the materials cache catches a disagreeing value
  on a cold cache, a warm cache and with caching off, including a scope swap.
- A caller cannot claim a scope through the context: `scope_ref`, `scope_id`,
  `tenant_ref` and `tenant_id` are refused.
- Message-dependent failures collapse to `:decrypt_failed`, and
  `Exception.message/1` never renders `:engine`.
- Truncation at every length, and a 1-bit flip at every position, of a
  5554-byte 0x0578 message never raised and never returned plaintext.
- Trailing bytes, and an engine return outside its contract, map to
  `:decrypt_failed` without carrying the engine's term.
- The strictest commitment policy is the default, and
  `:forbid_encrypt_allow_decrypt` is refused. The encrypted-data-key limit
  defaults to 10 and cannot be nil.
- The engine compares the key commitment with `:crypto.hash_equals/2`, and the
  comparisons this package does in Elixir are over public values.
- Read cache partitions are per vault and per selector.
- A suspension and a whole-scope shred are checked before the cache. F8 is the
  exception: they hold until the scope is provisioned again.
- Wrappings moved across scope or version fail on the required binding before
  any key material is touched.
- Key material in `use` options is a compile error. `Config` and `Key.Aes`
  redact their secrets from `inspect/2`.
- Telemetry metadata is an allow-list of tags and carries no terms.
- `derive/3` refuses the reserved purposes (F6's fix, which `aac183b`
  includes).
- The `Partition` and GCP KMS additional-data encodings are length-prefixed,
  so their fields cannot run together.

## The maintainer's review

The maintainer reviews the threat model and this ledger himself. His findings
are entered here verbatim, attributed "the maintainer", each with its own
F-entry, when he reviews the pull request that adds this ledger. That pull
request merges only after his approving review.

No entries yet.

## The findings

| Id | Severity | Found by | Disposition |
|---|---|---|---|
| F1 | High | the `python-interop` CI job | FIX IN PROGRESS |
| F2 | High | the `python-interop` CI job | FIX IN PROGRESS |
| F3 | High | the AWS Encryption SDK decrypt vectors | FIXED, PR 148 |
| F4 | Low | the SP 800-38D reading behind the threat model | DEFERRED to the engine |
| F5 | Medium | a review read of the 0.7.0 wire-format change | FIXED, PR 146 |
| F6 | High | a review read of the 0.7.0 wire-format change | FIXED, PR 147 |
| F7 | High | the LLM pass | FIXED, PR 156 |
| F8 | High | the LLM pass | FIXED, PR 158; the refusal after a shred DEFERRED to ece-qxuu |
| F9 | Medium | the LLM pass | FIXED by documentation, PR 159; the refusal DEFERRED to enc-5vyn |
| F10 | Medium | the LLM pass | FIXED, PR 157 |
| F11 | Medium | the LLM pass | FIXED, PR 154 |
| F12 | Medium | the LLM pass | FIXED by documentation, PR 160; the refusal DEFERRED to enc-d4yx |
| F13 | Low | the LLM pass | DEFERRED to enc-de5n |
| F14 | Low | the LLM pass | DEFERRED to enc-u4s6 |
| F15 | Low | the LLM pass | DEFERRED to enc-mo72 |
| F16 | Low/Info | the LLM pass | DEFERRED to enc-ssfx |

Under the rule above, F1 and F2 keep every release prep from merging until
each one is FIXED or the maintainer accepts it. They are the only open High
findings.

### F1. The engine stores required context keys in the message header

- **Where:** in the engine, at `a84686d`:
  `lib/aws_encryption_sdk/crypto/header_auth.ex:24-35`
  (`HeaderAuth.build_header/4`) stores the materials' whole context, required
  keys included. `lib/aws_encryption_sdk/cmm/default.ex:215`
  (`Cmm.Default.get_decryption_materials/2`) unwraps a message's data key under
  the stored context only.
- **Found by:** the `python-interop` CI job
  ([`test/encryptor/interop/python_interop_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/interop/python_interop_test.exs)).
  It runs the AWS Encryption SDK for Python 4.0.7. Every `:scoped` direction
  fails, because `scope_ref` is a required key in every message a `:scoped`
  vault writes.
- **Severity:** High.
- **Claim broken:** the README, at `26a25ef`, line 27: "the messages stay in
  the AWS format, readable from the official SDKs in other languages." The
  specification's rule that this breaks is quoted in the interop test's
  moduledoc: the stored context "MUST NOT contain any key value pairs listed in
  the encryption material's required encryption context keys".
- **Disposition:** FIX IN PROGRESS. The maintainer's disposition, given
  2026-10-06, is to fix it in the engine. The fix is merged there, in
  [aws-encryption-sdk-elixir PR 100](https://github.com/riddler/aws-encryption-sdk-elixir/pull/100),
  which also closes engine
  [issue #96](https://github.com/riddler/aws-encryption-sdk-elixir/issues/96).
  It ships in the engine's 1.1.0 release, which is not published yet, and
  this package does not yet require that release. This package moves to it
  as ADR-0004 Amendment B (proposed, on `main`) describes, and this entry
  turns FIXED when it does. Until then the README's
  Compatibility section and the threat model's "Known defects in the engine"
  name the failure. The interop test asserts each failing direction with its
  exact error.

### F2. The engine writes the signature verification key uncompressed

- **Where:** in the engine, at `a84686d`:
  `lib/aws_encryption_sdk/crypto/ecdsa.ex:52` (`ECDSA.encode_public_key/1`)
  base64-encodes the uncompressed point. It is called from
  `lib/aws_encryption_sdk/cmm/default.ex:198` for every signing suite.
- **Found by:** the `python-interop` CI job. The Python SDK decodes only the
  SEC 1 compressed form, so it cannot read any 0x0578 message the engine
  writes. 0x0578 is this package's default suite.
- **Severity:** High.
- **Claim broken:** the same README sentence as F1. The specification
  (`framework/transitive-requirements.md`) requires the compressed form.
- **Disposition:** FIX IN PROGRESS, in the same engine PR as F1, merged
  there and shipping in the same unpublished 1.1.0 release, which this
  package does not yet require. The engine
  reads both forms, so messages already written stay readable. The signature
  itself was never weak: either form encodes the same point.

### F3. A message followed by trailing bytes raised instead of being refused

- **Where:** encryptor at `6f5ee54`, `lib/encryptor/vault/decrypt.ex:220-221`
  (`Encryptor.Vault.Decrypt.engine_decrypt/5`). For a valid message followed by
  extra bytes, the engine returned `{:ok, message, rest}`, which is outside its
  own spec. The case had no clause for that shape. The engine side is
  `lib/aws_encryption_sdk/decrypt.ex:57` at `a84686d` (`Decrypt.decrypt/2`).
- **Found by:** the AWS Encryption SDK decrypt vectors. Five published raw-AES
  negative vectors (`5da80562`, `b46133ab`, `bacd259d`, `c03d1b84`,
  `e20df8c3`) made `Encryptor.Vault.decrypt/3` raise a `CaseClauseError` whose
  text rendered the parsed message. `rekey/3` shares that code and raised the
  same way. The raise returned no plaintext.
- **Severity:** High.
- **Claim broken:** the spec of `Encryptor.Vault.decrypt/3`, `{:ok, binary()}
  | {:error, Error.t()}`.
- **Disposition:** FIXED in
  [PR 148](https://github.com/riddler/encryptor/pull/148). Every return
  outside `{:ok, _}` and `{:error, _}` is now `:decrypt_failed`, carrying
  `:unexpected_engine_result` in `:engine` and not the engine's term. Two tests
  pin it, both named "a message followed by one trailing byte is
  decrypt_failed, carrying no engine term":
  - in `test/encryptor/vault/decrypt_test.exs`. Its sabotage note: carrying the
    engine's own return in `:engine` from `engine_result/3`'s catch-all, in
    place of `:unexpected_engine_result`, turns it red, and so does deleting
    the clause.
  - in `test/encryptor/vault/rekey_test.exs`. Its sabotage note: passing
    `:decrypt` instead of `operation` to `Error.decrypt_failed/3` in the
    catch-all turns it red.

  [`test/encryptor/vectors/aws_vectors_vault_decrypt_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vectors/aws_vectors_vault_decrypt_test.exs)
  ([PR 151](https://github.com/riddler/encryptor/pull/151)) now runs every
  raw-AES negative vector through `Vault.decrypt/3`. The engine's own refusal
  of trailing bytes is in its PR 100.

### F4. The engine has no maximum-frames guard

- **Where:** in the engine, at `a84686d`:
  `lib/aws_encryption_sdk/encrypt.ex:166` (`encrypt_body/4`). Nothing bounds
  the frame count at 2^32 - 1, the IV space the frame counter has under
  SP 800-38D section 8.3.
- **Found by:** the SP 800-38D reading for the threat model's "The limits of
  AES-GCM" section.
- **Severity:** Low. This package cannot reach the limit: `encrypt/2` takes
  the whole plaintext as one binary, and reaching the limit at the default
  4096-byte frame needs a plaintext of about 16 TiB.
- **Claim broken:** none of this package's. The threat model states the gap:
  "The engine has no guard on that frame count today."
- **Disposition:** DEFERRED to the engine, where a guard belongs. No engine
  tracker entry is named here.

### F5. A `:scoped` vault started with required context keys no call could supply

- **Where:** encryptor at `4dce7df`, `lib/encryptor/vault/config.ex:814-836`
  (`required_context_keys/3`). A `:scoped` vault with `scope_id` or
  `tenant_id` in `:required_context` started. After that, every encrypt
  failed: the caller is refused those keys, and the vault never injects them.
- **Found by:** a review read of the 0.7.0 wire-format change.
- **Severity:** Medium. The refusal held only partly: it covered the cases the
  code comment named and missed these two keys.
- **Claim broken:** the rule `required_context_keys/3` applies, stated in its
  own comment at `config.ex:820-821`: "requiring it there is a vault that can
  never encrypt". The function refused `"scope_ref"` on a `:single` vault and
  the retired spelling on both profiles, but not these two keys on a `:scoped`
  vault.
- **Disposition:** FIXED in
  [PR 146](https://github.com/riddler/encryptor/pull/146). A vault that
  requires a key no caller can supply on its profile now refuses to start with
  `{:invalid_config, :required_context, {:reserved_key, key}}`. The tests
  "a scoped vault may not require scope_id", with its sibling rows, in "the
  required context list"
  ([`test/encryptor/vault/config_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/config_test.exs))
  pin it. Their sabotage note: removing the reserved-key branch of
  `required_context_keys/3` turns every row red, because each vault then
  starts.

### F6. `derive/3` did not refuse the purposes its documentation reserved

- **Where:** encryptor at `1c35ecd`, `lib/encryptor/vault/derive.ex:65-75`
  (`Encryptor.Vault.Derive.call/3`), which passed any purpose to the key
  derivation.
- **Found by:** a review read of the 0.7.0 wire-format change.
- **Severity:** High. The documentation stated a refusal the code did not
  make.
- **Claim broken:** `lib/encryptor/vault/docs.ex:177-179` at `1c35ecd`, the
  generated `derive/2` docs: the purpose "may not be `"root-wrap"` or
  `"scope-ref"`, which name the trees this package derives for itself, or the
  retired `"tenant-ref"`".
- **Disposition:** FIXED in
  [PR 147](https://github.com/riddler/encryptor/pull/147). The three purposes
  are now refused with `{:invalid_config, :purpose, :reserved}` before the key
  provider is asked. The tests in "derive/3 refusals"
  ([`test/encryptor/vault/derive_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/derive_test.exs))
  pin it: "the root-wrap purpose is refused", "the scope-ref purpose is
  refused" and "the retired tenant-ref purpose is refused". Their sabotage
  note: removing the `purpose/2` step from `Derive.call/3`, so a reserved
  purpose reaches the key derivation, turns each one red. The change is listed
  under Breaking in the changelog.

### F7. Rekey and root rewrap are refused on the default signing suite

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/rekey.ex:135-148`
  (`rekey/6`). It passes the stored context, unchanged, to
  `Encrypt.engine_encrypt/5`. `lib/encryptor/envelope.ex:413-420`
  (`rewrap/2`) reaches the same code.
- **Found by:** the LLM pass. Reproduced: on suite 0x0578 the stored context
  holds the engine's reserved `aws-crypto-public-key`. Writing that context
  back is refused `{:invalid_config, :encrypt, :engine_refused}`, both on
  `Vault.rekey/2` and on `rewrap/2` for a root vault on the default suite.
  Every rekey and envelope test fixture uses 0x0478.
- **Severity:** High.
- **Claim broken:** `lib/encryptor/envelope.ex:35`, "root rotation is
  `rewrap/2` and nothing else", for a root vault left on the default suite.
  The rotation runbook's root-rotation step works only because the
  getting-started guide's root vault sets `algorithm_suite_id: 0x0478`.
- **Disposition:** FIXED in
  [PR 156](https://github.com/riddler/encryptor/pull/156), as the maintainer
  disposed it on 2026-10-07. The rekey's write half now writes the stored
  context less the engine's verification-key pair (`writable/1` in
  `Encryptor.Vault.Rekey`), and the engine writes a fresh pair for the new
  message. `rewrap/2` reaches the same write half. Tests on 0x0578 pin it:
  - in "on the signing suite, 0x0578"
    ([`test/encryptor/vault/rekey_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/rekey_test.exs)):
    "moves a message off a retired key, and it opens under the new one",
    "carries the host's pairs across, and the engine writes a fresh
    verification key" and "round trips on a scoped vault, with the pair the
    vault supplied itself";
  - in "rewrap/2 on the signing suite, 0x0578"
    ([`test/encryptor/envelope_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/envelope_test.exs)):
    "moves the wrapping onto the new root, and it unwraps to the identical
    descriptor" and "the binding is carried across, and only the engine's
    pair is renewed".

  Their sabotage note: passing the stored context to the re-encrypt in place
  of `writable(stored)` turns each one red, because the engine refuses its
  own verification-key pair from a caller.

### F8. Re-provisioning a shredded scope under the same key name revives old ciphertext

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/partition.ex:111-120`
  (`encryption_id/3`), `:145-148` (`identity/1`) and `:94-99` (`id/2`). The
  cache partition ids use only the key's namespace and name. The name gets
  reused because `provision/3` defaults to version 1
  (`lib/encryptor/envelope.ex:733-742`, `version/2`), and `lib/encryptor/provider/gcp_kms.ex:258,398-418` (`mint/4`)
  always mints version 1.
- **Found by:** the LLM pass. Reproduced on a scoped vault with the cache on.
  The steps: encrypt, warm the read entry, shred, then provision the same
  scope again with new random material under the same name. A message written
  before the shred decrypts again. The next encrypt reuses the warm write
  entry, so its data key is wrapped under the destroyed material. After a
  cache recycle, that new message no longer decrypts.
- **Severity:** High.
- **Claims broken:** the `Encryptor.Key.Aes` moduledoc
  (`lib/encryptor/key/aes.ex:38`), "A name is bound to bytes, forever."
  ADR-0001 Amendment B, "a new version is a new partition and a write after a
  mint is a cold miss". The rotation runbook's crypto-shred step 3, draining
  the caches, which it describes as "residency rather than readability".
- **Disposition:** FIXED in
  [PR 158](https://github.com/riddler/encryptor/pull/158), as the maintainer
  disposed it on 2026-10-07, in both halves the pass suggested:
  - **The cache.** Both cache partition ids now carry a fingerprint of the
    key material: the write side's over the resolved key
    (`Encryptor.Vault.Partition.encryption_id/3`), the read side's over the
    whole candidate list (`decryption_id/3`). The record is ADR-0001
    Amendment C. It is a cryptographic decision, so it stays proposed until
    the maintainer's own reading flips it. Two tests in "a re-provision under
    a shredded name"
    ([`test/encryptor/vault/remint_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/remint_test.exs))
    replay the reported sequence:
    - "does not revive a message written under the shredded bytes". Its
      sabotage note: leaving the material's fingerprint out of `identity/1`
      in `Encryptor.Vault.Partition`, for both sides, turns it red.
    - "writes a message that still decrypts after the cache is recycled". Its
      sabotage note: leaving the fingerprint out of `encryption_id/3` turns it
      red.
  - **The re-mint.** Where the GCP KMS provider can see that a scope's name
    is in use, a provision is refused with `{:key_name_in_use, selector}`
    before any GCP call. "refuses a scope the store already holds a row for,
    before any GCP call"
    ([`test/encryptor/provider/gcp_kms_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/provider/gcp_kms_test.exs))
    pins it. Its sabotage note: making `unused/3` answer `:ok` for every
    store answer turns it red.

  The provider cannot see a used name after a whole-scope shred has deleted
  the store's rows, and `Encryptor.Envelope.provision/3` sees no store.
  Refusing a re-insert after a shred is the key store's to do: DEFERRED to
  ece-qxuu, in encryptor_ecto's tracker. The fingerprint keeps the cache safe
  either way.

### F9. A per-call context key the message never stored is not compared

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/decrypt.ex:199-211`
  (`compare/4`). It compares only the keys present in both the stored and the
  reproduced context. `:required_context` defaults to `[]`
  (`lib/encryptor/vault/config.ex:362`).
- **Found by:** the LLM pass. Reproduced on a cold and a warm cache: a
  ciphertext written under `%{"blob" => "avatar"}`, or under no context,
  decrypts under a `table`/`column` claim.
- **Severity:** Medium. The binding holds when both writers used the same keys,
  or when `:required_context` names them.
- **Claims broken:** the threat model: "A value moved to another column ...
  fails to decrypt rather than decrypting into the wrong place, because both
  are bound to where they were written", and "a decrypt under a context that
  disagrees with the message fails".
- **Disposition:** FIXED by documentation in
  [PR 159](https://github.com/riddler/encryptor/pull/159), as the maintainer
  disposed it on 2026-10-07. The threat model, the security model, the
  getting-started guide and the `Encryptor.Context` moduledoc now say that a
  context key binds a message only when the message carries it, which the
  vault's `:required_context` guarantees, as does a writer that passes it on
  every call. The README's decrypt example no longer says a decrypt under any
  other context fails. Two
  tests in "the vault-side reproduced-context value check"
  ([`test/encryptor/vault/decrypt_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/decrypt_test.exs))
  pin today's behaviour:
  - "a message written without a column reads under any column claim". Its
    sabotage note: replacing `Map.get(stored, key, value)` with
    `Map.get(stored, key)` in `compare/4` turns it red.
  - "a vault requiring the column refuses a message written without it". Its
    sabotage note: making `maybe_required/2` return the materials manager
    unwrapped for every config turns it red.

  Refusing a per-call key the stored context lacks is DEFERRED to enc-5vyn.

### F10. A root vault used as an application vault returns a scope master key

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/decrypt.ex:131-165`
  (`call/4` on the public path). Nothing on that path refuses a message whose
  stored context carries an `encryptor-` key, and nothing stops a host from
  using its root vault as an application vault.
- **Found by:** the LLM pass. Reproduced: `RootVault.decrypt/1` of a wrapping
  returns the same 32 bytes `unwrap/2` yields, also under a `table`/`column`
  claim. A host whose root vault is also an application vault lets anyone who
  can write a column the host decrypts and displays extract a scope master
  key.
- **Severity:** Medium. It needs a host configuration the guides do not
  describe.
- **Claims broken:** `lib/encryptor/envelope.ex:42-43`, "There is no function
  in this package that returns a bare scope master key as a binary."
  `docs/explanation/security-model.md:101`, "The plaintext key is never handed
  back."
- **Disposition:** FIXED in
  [PR 157](https://github.com/riddler/encryptor/pull/157), as the maintainer
  disposed it on 2026-10-07. The public decrypt and rekey, on a root vault as
  on any other, refuse a message whose stored context carries an
  `encryptor-` key the reader did not reproduce, with `:decrypt_failed`
  (`compare/4` in `Encryptor.Vault.Decrypt`). No host can write such a key,
  so every scope-key wrapping is refused there. `Encryptor.Envelope` keeps an
  internal path: `unwrap/2` and `rewrap/2` reproduce the binding and enter
  the decrypt and rekey code below the public functions. Tests in "a root
  vault's public decrypt and rekey refuse a wrapping"
  ([`test/encryptor/envelope_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/envelope_test.exs))
  pin it, among them:
  - "decrypt/2 refuses it, naming the first binding key in :engine". Its
    sabotage note: removing the package-reserved clause from `compare/4`
    turns it red, because the decrypt then returns the 32-byte scope master
    key.
  - "rekey/2 refuses it, stamped :rekey". Its sabotage note: the same
    removal turns it red.

### F11. `inspect/2` of an `Encryptor.Error` rendered a provider's own failure term

- **Where:** encryptor at `aac183b`, `lib/encryptor/error.ex:117`. The
  `defexception` had no `Inspect` implementation, so `inspect/2` rendered
  `:engine` and the reason details. Terms reached `:engine` from
  `lib/encryptor/vault/config.ex:623-627` (`provider_init_error/2`) and
  `lib/encryptor/vault/resolve.ex:182-185` (`off_contract/3`).
- **Found by:** the LLM pass. Reproduced with a custom provider whose `init/1`
  error term held a key-length value. `inspect/2` of the start result showed
  it, and so did a parent supervisor's failed-start report.
  `Exception.message/1` was clean.
- **Severity:** Medium.
- **Claims broken:** `lib/encryptor/vault/config.ex:619`, "carried in
  `:engine`, which is never rendered, because a provider's own failure term can
  hold key material". The threat model: "no plaintext, data key or wrapping
  key material ever appears in an error message, an `inspect/2` result or a
  telemetry event".
- **Disposition:** FIXED in
  [PR 154](https://github.com/riddler/encryptor/pull/154). `Encryptor.Error`
  now has an `Inspect` implementation that shows `:engine`, and the details of
  `{:invalid_config, key, detail}` and `{:invalid_key_descriptor, detail}`, as
  `"[redacted]"`. Provider answers outside the contract are reduced to the
  vault's own terms. Two tests pin it:
  - "never renders the engine term", in "inspect/2"
    ([`test/encryptor/error_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/error_test.exs)).
    Its sabotage note: rendering `error.engine` unredacted in the `Inspect`
    implementation turns it red.
  - "keeps a provider's own init term out of inspect/2"
    ([`test/encryptor/vault/inspect_redaction_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/inspect_redaction_test.exs)).
    Its sabotage note: deleting the `Inspect` implementation turns it red, and
    so does rendering the engine term unredacted.

### F12. A signing vault accepts an unsigned message

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/decrypt.ex:153-165`.
  Nothing checks the message's suite against the vault's
  `algorithm_suite_id`; the suite is used only on write.
- **Found by:** the LLM pass. Reproduced: a 0x0578 vault accepts a 0x0478
  (unsigned) message under the same key. Reasoned, not reproduced: with a raw
  key provider the reader holds the wrapping key and can write new messages
  anyway, so signing prevents forgery only on the KMS path with decrypt-only
  grants.
- **Severity:** Medium.
- **Claim broken:** `guides/getting-started.md:150-152`, "Keep `0x0578` when a
  ciphertext crosses a trust boundary: written by one service and read by
  another that should not be able to forge it". The suite guidance in
  `lib/encryptor/vault/config.ex:165-176` says the same.
- **Disposition:** FIXED by documentation in
  [PR 160](https://github.com/riddler/encryptor/pull/160), as the maintainer
  disposed it on 2026-10-07. The getting-started guide, the suite section of
  `Encryptor.Vault.Config`'s moduledoc and the threat model now say that the
  signature stops a reader forging only where that reader cannot wrap a data
  key of its own: an AWS KMS key whose grants give the reader decrypt and
  nothing that wraps. A key that reaches the vault as AES material, from raw
  key material or from the GCP KMS provider, is in every reader's hands, so
  signing does not prevent forgery there. They also say that decrypt does not
  check a message's suite. "a signing-suite vault reads an unsigned message
  under the same key", in "the suite a message was written under"
  ([`test/encryptor/vault/decrypt_test.exs`](https://github.com/riddler/encryptor/blob/main/test/encryptor/vault/decrypt_test.exs)),
  pins today's behaviour. Its sabotage note: making `agree/4` refuse a
  message whose suite differs from the configured one turns it red.

  Refusing a suite other than the configured one on decrypt is DEFERRED to
  enc-d4yx.

### F13. `derive/3` raises for some bad input instead of returning its error

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/derive.ex:95-99,125-131`
  (`purpose/2`, `out_length/2`) and `lib/encryptor/kdf.ex:234-245,317-320`.
- **Found by:** the LLM pass. Reproduced: `length: 9000`, purpose `"a/b"` and
  purpose `""` each raise `ArgumentError`.
- **Severity:** Low.
- **Claim broken:** the spec of `Vault.derive/3`, `{:ok, binary()} | {:error,
  Error.t()}`.
- **Disposition:** DEFERRED to enc-de5n.

### F14. `unwrap/2` and `rewrap/2` do not bind the stored key name and size

- **Where:** encryptor at `aac183b`, `lib/encryptor/envelope.ex:370-386,600-608`.
  `unwrap/2` takes `name` and `bits` from the row, and the binding covers
  neither.
- **Found by:** the LLM pass. Reasoned: a database writer can rename a row's
  key name. That costs availability (the encrypted data key's name no longer
  matches) but discloses nothing.
- **Severity:** Low.
- **Claim:** the threat model's key-store rows carry the "name and key size
  that identify it", and "A row moved to another scope or version must not
  unwrap".
- **Disposition:** DEFERRED to enc-u4s6.

### F15. The GCP KMS provider does not check a row's scope reference

- **Where:** encryptor at `aac183b`,
  `lib/encryptor/provider/gcp_kms.ex:459-515` (`rows/2`, `validate_row/1`).
- **Found by:** the LLM pass. Reasoned: the provider never checks that
  `row.scope_ref` equals the reference derived from the selector. The
  additional data binds the row to its own claim, so safety depends on the
  host's store filtering by that field.
- **Severity:** Low.
- **Claim:** the threat model's "A row moved to another scope or version must
  not unwrap".
- **Disposition:** DEFERRED to enc-mo72.

### F16. The suspension view is a public ETS table

- **Where:** encryptor at `aac183b`, `lib/encryptor/vault/suspension.ex:114`
  (`create/1` creates a `:public` named ETS table).
- **Found by:** the LLM pass. Reasoned: any process in the node can lift a
  suspension. The threat model puts compromise of the host process out of
  scope, so no documented claim breaks.
- **Severity:** Low/Info.
- **Claim:** none broken.
- **Disposition:** DEFERRED to enc-ssfx, as hardening (`:protected`).
