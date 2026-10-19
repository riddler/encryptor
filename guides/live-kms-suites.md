# Running the live KMS suites

This page is for maintainers of this repository. It is not part of the
published documentation: a host using the package never runs these suites.

Every provider test in the default suite runs against an in-memory fake at
the HTTP boundary, so `mix test` needs no network and no credential. The live
suites are the one place a provider meets the real service. They are tagged,
excluded by default in `test/test_helper.exs`, and run by their own CI jobs.

## Cloud KMS (`Encryptor.Provider.GcpKms`)

The suite is `test/encryptor/provider/gcp_kms_live_test.exs`, tagged
`:gcp_kms_integration`. It provisions a scope on one test key, checks that
`Decrypt` hands back exactly the bytes `Encrypt` wrapped, checks that a
wrapping read under another scope's binding is refused, and checks that a key
the credentials hold no grant on answers `key_unavailable`. It never creates
a `CryptoKey`: every provider state it builds names the test key.

### What it needs

- A test key the credentials may encrypt and decrypt with, and a second key
  they hold no grant on. Use dedicated keys in a sandbox project, never a key
  that protects real data.
- Two environment variables naming those keys, each a full `CryptoKey`
  resource name of the form
  `projects/*/locations/*/keyRings/*/cryptoKeys/*`:
  - `GCP_KMS_KEY` - the usable test key;
  - `GCP_KMS_DENIED_KEY` - the key with no grant.
- Credentials, read in this order:
  - the file `GOOGLE_APPLICATION_CREDENTIALS` names (a service account key, a
    Workload Identity Federation file, or a user's Application Default
    Credentials file);
  - otherwise the gcloud CLI's Application Default Credentials file, which
    `gcloud auth application-default login` writes.

### Running it locally

From the repository root, with the two key names exported in your shell and
Application Default Credentials in place:

```bash
gcloud auth application-default login
mix test --only gcp_kms_integration
```

With either key name unset or empty, the four tests are reported as skipped
rather than failed, so the command is safe to run without credentials. Set
`ENCRYPTOR_REQUIRE_GCP_KMS=1` to make an absent key name a failure instead,
as CI does.

Keep the key names out of anything you share. A failing test reports a call
kind, an HTTP status or a reason term, and never a key name, a project, a
key ring or key material; do not add output that would.

### How CI runs it

The `gcp-kms-integration` job in `.github/workflows/ci.yml` authenticates with
Workload Identity Federation (no key file) through
`google-github-actions/auth`, and reads the provider, the service account and
both key names from organisation secrets. It runs only when all four secrets
are present and the event is not from a fork or Dependabot; otherwise it is a
green job whose one step says it skipped. The job is informational: no branch
rule requires it.

## AWS KMS (`Encryptor.Provider.Kms`)

The suite is `test/encryptor/provider/kms_live_test.exs`, tagged
`:aws_kms_integration`. It starts a `:scoped` vault whose provider names one
test key, and checks three things:

- a provision answers `{:not_provisionable, Encryptor.Provider.Kms}`, because
  the provider creates no keys, and calls KMS for nothing;
- a write calls `GenerateDataKey` on the test key, and a read of that message
  calls `Decrypt` and hands back exactly the plaintext written;
- the same message read under another scope is refused by KMS with
  `InvalidCiphertextException`, and the vault answers `:decrypt_failed`. This
  is the suite's wrong-key case: the read names the right key under a scope
  the data key was not generated for. KMS is asked twice, because the engine
  retries once under the message's stored context, and refuses both.

It never creates, disables or deletes a key.

The suite talks to KMS through its own small client
(`Encryptor.AwsKmsLive.Client`, in `test/support/aws_kms_live.ex`), handed
to the provider as `:client`. This package declares no AWS dependency, so
the engine's shipped `ExAws` client, which `:region` would build, is not in
the build.

### What it needs

- A symmetric KMS key the credentials may call `GenerateDataKey` and
  `Decrypt` on. Use a dedicated key in a sandbox account, never a key that
  protects real data.
- `KMS_KEY_ARN`, the key's full ARN, of the form
  `arn:aws:kms:<region>:<account>:key/<key id>`.
- Credentials in the environment: `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` when they are temporary
  (an assumed role's or an SSO session's always are). The suite reads these
  three variables and nothing else: no profile file, no instance metadata.

The requests go to the region the key's ARN names; `AWS_REGION` is not read.

### Running it locally

From the repository root, with `KMS_KEY_ARN` exported in your shell. If your
credentials live in a named profile or an SSO session, the AWS CLI exports
them as the variables above:

```bash
eval "$(aws configure export-credentials --profile <profile> --format env)"
mix test --only aws_kms_integration
```

With `KMS_KEY_ARN` unset or empty, the three tests are reported as skipped
rather than failed, so the command is safe to run without credentials. Set
`ENCRYPTOR_REQUIRE_AWS_KMS=1` to make an absent ARN a failure instead, as CI
does.

Keep the ARN and the credentials out of anything you share. A failing test
reports a call kind, an HTTP status or a reason tag; the client keeps only
the error type of a KMS refusal, because KMS's own message can name the key
and the caller. Do not add output that would print any of them.

### How CI runs it

The `aws-kms-integration` job in `.github/workflows/ci.yml` assumes a role
with the job's GitHub OIDC token (no static access key), the same role the
aws-encryption-sdk-elixir integration tests assume. The assumption is one
silent run step calling `aws sts assume-role-with-web-identity` for the
credentials alone: it masks each value before writing it, prints no part of
the response and no message from the call, and fails with one fixed line.
It reads the role and the key's ARN from organisation secrets. It runs
only when both secrets are present and the event is not from a fork or
Dependabot; otherwise it is a green job whose one step says it skipped. The
job is informational: no branch rule requires it.
