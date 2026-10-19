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
