# Measures the bounds four accepted records state but do not derive.
#
#     mix run bench/bounds.exs
#
# Companion to docs/measurements/260912-enc-anz-stated-bounds.md, which is
# where the numbers this prints are read. Re-run it before citing that note
# on a different machine: every timing here is machine-local, and the note
# records the machine it was taken on.
#
# What is in scope (enc-anz):
#
#   1. `max_messages: 100` and `max_bytes: 1 GiB`   ADR-0001 open question 2
#   2. `recycle_after: 20 * max_age` under a        ADR-0004 open question 6
#      per-column cache partitioning
#   3. the 32-pair and 4 KiB context bounds         ADR-0004 open question 4
#   4. the 32-byte tenant master key and 0x0478     ADR-0003 open question 7
#   5. the Argon2id 64 MiB / 3-iteration parameters ADR-0003 amendment B4
#      (proposed, not accepted - measured as an addendum)
#
# This harness MEASURES. It does not retune. Nothing here writes a default,
# and a number that contradicts a record is a finding for the operator, not
# an edit to the record.
#
# The honest limit of every number below: the providers are in-memory. A
# cache miss here pays the engine's data-key generation and EDK wrap, and a
# `Function` provider's closure, and nothing else. A store-backed or KMS
# provider adds its own round trip on top, and the note says where.

defmodule Bench.Report do
  @moduledoc false

  def section(title) do
    IO.puts("\n" <> String.duplicate("=", 72))
    IO.puts(title)
    IO.puts(String.duplicate("=", 72))
  end

  def row(label, value), do: IO.puts(String.pad_trailing(label, 46) <> to_string(value))

  def table(headers, rows) do
    widths =
      [headers | rows]
      |> Enum.zip_with(fn column ->
        column |> Enum.map(&String.length(to_string(&1))) |> Enum.max()
      end)

    IO.puts(line(headers, widths))
    IO.puts(Enum.map_join(widths, "  ", &String.duplicate("-", &1)))
    Enum.each(rows, &IO.puts(line(&1, widths)))
  end

  defp line(cells, widths) do
    cells
    |> Enum.zip(widths)
    |> Enum.map_join("  ", fn {cell, width} -> String.pad_trailing(to_string(cell), width) end)
  end

  # Microseconds per call, over `n` calls, after a warmup of the same shape.
  # The median of five batches rather than one mean: a single batch on a
  # laptop picks up whatever else the machine was doing.
  def micros(n, fun) do
    Enum.each(1..min(n, 50), fn _ -> fun.() end)

    1..5
    |> Enum.map(fn _ ->
      {elapsed, :ok} = :timer.tc(fn -> Enum.each(1..n, fn _ -> fun.() end) end)
      elapsed / n
    end)
    |> Enum.sort()
    |> Enum.at(2)
  end

  def round2(float), do: Float.round(float * 1.0, 2)
end

defmodule Bench.Vaults do
  @moduledoc false

  # A single-key vault, suite configurable, cache configurable. One module per
  # configuration because `use Encryptor.Vault` freezes the module name into
  # the partition id and the config lookup.

  defmodule Cached0478 do
    use Encryptor.Vault, otp_app: :encryptor
  end

  defmodule Cached0578 do
    use Encryptor.Vault, otp_app: :encryptor
  end

  defmodule Uncached0478 do
    use Encryptor.Vault, otp_app: :encryptor
  end

  defmodule Uncached0578 do
    use Encryptor.Vault, otp_app: :encryptor
  end

  # Same as Cached0478 but with max_messages far above anything a batch will
  # reach, so the cost of re-deriving materials every 100 messages can be
  # separated from the cost of consulting the cache at all.
  defmodule CachedLooseMessages do
    use Encryptor.Vault, otp_app: :encryptor
  end

  # `max_messages: 1` forces a miss on every call after the first. It is the
  # discriminator for the whole cache section: if this vault is not measurably
  # slower than `CachedLooseMessages`, then no call was ever a hit and the
  # "what the cache costs" numbers are not measuring what they claim to.
  defmodule CachedTightMessages do
    use Encryptor.Vault, otp_app: :encryptor
  end

  defmodule Root do
    use Encryptor.Vault, otp_app: :encryptor
  end

  defmodule Tenant do
    use Encryptor.Vault, otp_app: :encryptor
  end

  @key_bytes 32

  def start_all do
    key = :crypto.strong_rand_bytes(@key_bytes)

    single(Cached0478, key, 0x0478, max_age: 60)
    single(Cached0578, key, 0x0578, max_age: 60)
    single(Uncached0478, key, 0x0478, false)
    single(Uncached0578, key, 0x0578, false)
    single(CachedLooseMessages, key, 0x0478, max_age: 60, max_messages: 1_000_000)
    single(CachedTightMessages, key, 0x0478, max_age: 60, max_messages: 1)

    root_material = :crypto.strong_rand_bytes(@key_bytes)
    root(Root, root_material)

    %{key: key, root: root_material}
  end

  defp single(module, key, suite, cache) do
    Application.put_env(:encryptor, module,
      context_profile: :single,
      algorithm_suite_id: suite,
      provider: {Encryptor.Provider.Static, key: key, namespace: "bench", name: "bench/v1"},
      cache: cache
    )

    {:ok, _pid} = module.start_link([])
    module
  end

  defp root(module, root_material) do
    Application.put_env(:encryptor, module,
      context_profile: :single,
      algorithm_suite_id: 0x0478,
      provider:
        {Encryptor.Provider.Static,
         key: Encryptor.Envelope.root_subkey(root_material, "root-wrap"),
         namespace: "encryptor-root",
         name: "r/v1"},
      cache: false
    )

    {:ok, _pid} = module.start_link([])
    module
  end

  # A tenant vault whose provider closure counts its own calls, so the
  # "is the provider consulted per call or per partition per max_age"
  # question has a number rather than a reading of two records.
  def start_tenant(counter, descriptors) do
    Application.put_env(:encryptor, Tenant,
      context_profile: :tenant,
      algorithm_suite_id: 0x0478,
      reference_subkey:
        Encryptor.Envelope.root_subkey(:crypto.strong_rand_bytes(32), "tenant-ref"),
      provider:
        {Encryptor.Provider.Function,
         encryption_key: fn selector ->
           :counters.add(counter, 1, 1)
           fetch(descriptors, selector)
         end,
         decryption_keys: fn selector ->
           :counters.add(counter, 1, 1)

           case fetch(descriptors, selector) do
             {:ok, descriptor} -> {:ok, [descriptor]}
             other -> other
           end
         end},
      cache: [max_age: 60]
    )

    {:ok, _pid} = Tenant.start_link([])
    Tenant
  end

  defp fetch(descriptors, selector) do
    case Map.fetch(descriptors, selector) do
      {:ok, descriptor} -> {:ok, descriptor}
      :error -> {:error, {:unknown_key, selector}}
    end
  end
end

alias Bench.Report
alias Bench.Vaults

secrets = Vaults.start_all()

payload_small = :crypto.strong_rand_bytes(16)
payload_column = :crypto.strong_rand_bytes(64)
payload_blob = :crypto.strong_rand_bytes(4096)

canonical_ctx = %{"table" => "payment_methods", "column" => "number"}

# ---------------------------------------------------------------------------

Report.section("0. Machine and build")

Report.row("elixir", System.version())
Report.row("otp", System.otp_release())
Report.row("schedulers online", System.schedulers_online())
Report.row("encryptor", Application.spec(:encryptor, :vsn))
Report.row("aws_encryption_sdk", Application.spec(:aws_encryption_sdk, :vsn))
Report.row("argon2_elixir loaded?", Code.ensure_loaded?(Argon2.Base))

# ---------------------------------------------------------------------------

Report.section("3. Context bounds: 32 pairs and 4 KiB (ADR-0004 OQ4)")

Report.row("max_pairs/0", Encryptor.Context.max_pairs())
Report.row("max_bytes/0", Encryptor.Context.max_bytes())
Report.row("canonical keys", inspect(Encryptor.Context.canonical_keys()))

# What a real context actually costs. The tenant row is what a :tenant vault
# composes: the caller's pairs plus the vault-injected tenant_ref, plus the
# static pairs a host configures.
realistic =
  [
    {"single, table+column", canonical_ctx},
    {"single, +app", Map.put(canonical_ctx, "app", "acme_payments")},
    {"tenant, +tenant_ref",
     Map.merge(canonical_ctx, %{
       "app" => "acme_payments",
       "tenant_ref" => String.duplicate("a", 22)
     })},
    {"tenant, +purpose",
     Map.merge(canonical_ctx, %{
       "app" => "acme_payments",
       "tenant_ref" => String.duplicate("a", 22),
       "purpose" => "pii"
     })},
    {"blob-shaped",
     %{
       "blob" => "signup_wizard_variant_b",
       "purpose" => "pii",
       "app" => "acme_payments",
       "tenant_ref" => String.duplicate("a", 22)
     }}
  ]

Report.table(
  ["context", "pairs", "of 32", "bytes", "of 4096"],
  Enum.map(realistic, fn {label, ctx} ->
    size = Encryptor.Context.serialized_size(ctx)

    [
      label,
      map_size(ctx),
      "#{Report.round2(map_size(ctx) / Encryptor.Context.max_pairs() * 100)}%",
      size,
      "#{Report.round2(size / Encryptor.Context.max_bytes() * 100)}%"
    ]
  end)
)

# Which bound binds first. Sweep pair count at a realistic key/value width and
# see whether 32 pairs or 4096 bytes is reached first.
pad = fn n, width -> String.duplicate("k", width) <> Integer.to_string(n) end

sweep =
  for pairs <- [1, 2, 4, 8, 16, 32] do
    ctx = Map.new(1..pairs, fn n -> {pad.(n, 8), pad.(n, 24)} end)
    size = Encryptor.Context.serialized_size(ctx)
    {:ok, ct} = Vaults.Cached0478.encrypt(payload_column, encryption_context: ctx)

    micros =
      Report.micros(200, fn ->
        {:ok, _} = Vaults.Cached0478.encrypt(payload_column, encryption_context: ctx)
        :ok
      end)

    [pairs, size, byte_size(ct), Report.round2(micros)]
  end

Report.table(["pairs", "ctx bytes", "ciphertext bytes", "encrypt us"], sweep)

# The widest context the pair bound admits, and the widest the byte bound
# admits. If the byte bound is unreachable at 32 pairs of sane width, the
# 4 KiB bound never binds in practice and only the pair bound does.
widest_at_32 =
  Map.new(1..32, fn n ->
    {String.pad_leading(Integer.to_string(n), 3, "0") <> String.duplicate("k", 61),
     String.duplicate("v", 61)}
  end)

Report.row(
  "32 pairs x 64B key + 64B value, bytes",
  Encryptor.Context.serialized_size(widest_at_32)
)

two_pair_to_4k = %{
  "table" => String.duplicate("t", 2000),
  "column" => String.duplicate("c", 2000)
}

Report.row("2 pairs x ~2 KiB values, bytes", Encryptor.Context.serialized_size(two_pair_to_4k))

# serialized_size is 2 + sum(4 + |k| + |v|) (context.ex:252-261), so the two
# bounds cross at the per-pair width where 32 pairs exactly fill 4096 bytes.
crossover = div(Encryptor.Context.max_bytes() - 2, Encryptor.Context.max_pairs()) - 4

Report.row("crossover: |k|+|v| where both bind, B", crossover)

Report.row(
  "  below that width, the binding bound is",
  "max_pairs (32)"
)

Report.row(
  "  above that width, the binding bound is",
  "max_bytes (4096)"
)

# ---------------------------------------------------------------------------

Report.section("1. Cache bounds: max_messages 100, max_bytes 1 GiB (ADR-0001 OQ2)")

warm_ctx = %{"table" => "payment_methods", "column" => "number"}
{:ok, _} = Vaults.Cached0478.encrypt(payload_column, encryption_context: warm_ctx)

warm_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.Cached0478.encrypt(payload_column, encryption_context: warm_ctx)
    :ok
  end)

nocache_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.Uncached0478.encrypt(payload_column, encryption_context: warm_ctx)
    :ok
  end)

{:ok, _} = Vaults.CachedLooseMessages.encrypt(payload_column, encryption_context: warm_ctx)

loose_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.CachedLooseMessages.encrypt(payload_column, encryption_context: warm_ctx)
    :ok
  end)

Report.row("cache: false, us/encrypt", Report.round2(nocache_us))
Report.row("cache on, max_messages 100, us/encrypt", Report.round2(warm_us))
Report.row("cache on, max_messages 1e6, us/encrypt", Report.round2(loose_us))
Report.row("cache at the default bound costs, us", Report.round2(warm_us - nocache_us))
Report.row("cache with the bound relaxed costs, us", Report.round2(loose_us - nocache_us))
Report.row("re-derivation every 100 messages costs, us", Report.round2(warm_us - loose_us))

# The same comparison on the decrypt side. A decryption cache hit skips the
# EDK unwrap, which is the half of the work the encryption cache cannot skip,
# so if the cache pays for itself anywhere on a raw-AES keyring it is here.
{:ok, sample_ct} = Vaults.Cached0478.encrypt(payload_column, encryption_context: warm_ctx)

dec_cached_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.Cached0478.decrypt(sample_ct, encryption_context: warm_ctx)
    :ok
  end)

dec_nocache_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.Uncached0478.decrypt(sample_ct, encryption_context: warm_ctx)
    :ok
  end)

{:ok, _} = Vaults.CachedTightMessages.encrypt(payload_column, encryption_context: warm_ctx)

tight_us =
  Report.micros(2000, fn ->
    {:ok, _} = Vaults.CachedTightMessages.encrypt(payload_column, encryption_context: warm_ctx)
    :ok
  end)

Report.row("cache on, max_messages 1 (all misses), us", Report.round2(tight_us))

Report.row(
  "discriminator: miss minus hit, us",
  Report.round2(tight_us - loose_us)
)

Report.row(
  "  cache hits are real?",
  if(tight_us - loose_us > 0.5, do: "yes - misses cost more", else: "NO - section invalid")
)

Report.row("decrypt cache: false, us", Report.round2(dec_nocache_us))
Report.row("decrypt cache on, us", Report.round2(dec_cached_us))
Report.row("what a decryption cache hit saves, us", Report.round2(dec_nocache_us - dec_cached_us))

warm_rate = 1_000_000 / warm_us
Report.row("warm encrypts/sec (1 process)", Report.round2(warm_rate))

# How long the two bounds take to bind, at that rate and at realistic sizes.
# In milliseconds, because on this machine the message bound binds in about
# one.
Report.table(
  ["payload", "ms to 100 messages", "ms to 1 GiB", "which binds first"],
  Enum.map(
    [
      {"16 B", 16},
      {"64 B (column)", 64},
      {"4 KiB (blob)", 4096},
      {"1 MiB", 1_048_576},
      {"11 MiB", 11_534_336}
    ],
    fn {label, bytes} ->
      to_messages = 100 / warm_rate * 1000
      to_bytes = 1_073_741_824 / (warm_rate * bytes) * 1000

      [
        label,
        Report.round2(to_messages),
        Report.round2(to_bytes),
        if(to_messages < to_bytes, do: "max_messages", else: "max_bytes")
      ]
    end
  )
)

Report.row("payload where max_bytes binds first, B", div(1_073_741_824, 100))
Report.row("max_age 60 would cover, messages", round(warm_rate * 60))
Report.row("max_messages 100 covers, ms", Report.round2(100 / warm_rate * 1000))

Report.row(
  "max_age:max_messages lifetime ratio",
  Report.round2(60 / (100 / warm_rate))
)

# ---------------------------------------------------------------------------

Report.section("1b. Is the provider consulted per call or per partition?")

# ADR-0001 decision 2 and ADR-0002 decision 2 read differently; encrypt.ex
# flags the tension and takes decision 2's reading. This counts.
counter = :counters.new(1, [:atomics])

root_material = secrets.root
reference_subkey = Encryptor.Envelope.root_subkey(root_material, "tenant-ref")

tenant_ids = Enum.map(1..8, &"merchant-#{&1}")

descriptors =
  Map.new(tenant_ids, fn id ->
    {:ok, wrapped} =
      Encryptor.Envelope.provision(Vaults.Root, id,
        reference_subkey: reference_subkey,
        namespace: "bench-merchant"
      )

    {:ok, descriptor} = Encryptor.Envelope.unwrap(Vaults.Root, wrapped)
    {id, descriptor}
  end)

tenant_vault = Vaults.start_tenant(counter, descriptors)

before_count = :counters.get(counter, 1)

Enum.each(1..500, fn _ ->
  {:ok, _} =
    tenant_vault.encrypt(payload_column, key: "merchant-1", encryption_context: warm_ctx)
end)

after_count = :counters.get(counter, 1)

Report.row("encrypts on one warm partition", 500)
Report.row("provider closure calls", after_count - before_count)

Report.row(
  "reading the implementation follows",
  if(after_count - before_count >= 500,
    do: "ADR-0001 d2 (per call)",
    else: "ADR-0002 d2 (per partition per max_age)"
  )
)

# ---------------------------------------------------------------------------

Report.section("2. Cache cardinality and recycle_after (ADR-0004 OQ6)")

# The partition id is f(vault, selector) only. The engine's cache id is
# f(partition_id, suite, serialized context). So the entry count is tenants
# times distinct contexts, and the partition buys separation, not cardinality.
alias AwsEncryptionSdk.AlgorithmSuite
alias AwsEncryptionSdk.Cmm.Caching

suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

columns =
  for table <- ["payment_methods", "merchants", "contacts", "documents", "audit"],
      column <- ["number", "holder", "email", "address", "notes"],
      do: %{"table" => table, "column" => column}

partitions = Enum.map(tenant_ids, &Encryptor.Vault.Partition.id(Vaults.Tenant, &1))

cache_ids =
  for partition <- partitions, ctx <- columns do
    Caching.compute_encryption_cache_id(partition, suite, ctx)
  end

Report.row("tenants", length(tenant_ids))
Report.row("distinct contexts (tables x columns)", length(columns))
Report.row("distinct partition ids", partitions |> Enum.uniq() |> length())
Report.row("distinct cache ids", cache_ids |> Enum.uniq() |> length())
Report.row("entries per tenant", length(columns))

# Memory per live entry: fill one cache with N distinct contexts on one
# partition and take the delta the VM reports for ETS.
# Only the ETS figure is reported. `:erlang.memory(:total)` over the same
# window is dominated by process heaps and GC timing and came back negative on
# a run where ETS grew cleanly, so it measures the machine's mood rather than
# the cache.
:erlang.garbage_collect()
ets_before = :erlang.memory(:ets)

fill = 500

Enum.each(1..fill, fn n ->
  {:ok, _} =
    Vaults.Cached0478.encrypt(payload_small,
      encryption_context: %{"table" => "t", "column" => "c#{n}"}
    )
end)

:erlang.garbage_collect()
ets_after = :erlang.memory(:ets)

per_entry_ets = (ets_after - ets_before) / fill

Report.row("entries written", fill)
Report.row("ETS bytes/entry", Report.round2(per_entry_ets))

Report.table(
  ["tenants", "columns", "entries", "ETS MiB"],
  Enum.map(
    [{100, 10}, {1_000, 10}, {1_000, 25}, {10_000, 10}, {10_000, 25}],
    fn {tenants, cols} ->
      entries = tenants * cols
      [tenants, cols, entries, Report.round2(entries * per_entry_ets / 1_048_576)]
    end
  )
)

Report.row("recycle_after default at max_age 60, sec", 20 * 60)

# What recycle_after actually bounds is the number of entries the table can
# hold before it is dropped whole. That ceiling is the number of DISTINCT
# (tenant, context) pairs touched in the window, not a rate - a busy vault
# re-touches the same entries. So the peak is the reachable cardinality, and
# recycle_after only helps where tenants churn faster than the window.
Report.table(
  ["active tenants in 1200s", "columns", "peak entries", "peak ETS MiB"],
  Enum.map(
    [{50, 10}, {500, 10}, {5_000, 10}, {50_000, 10}],
    fn {tenants, cols} ->
      entries = tenants * cols
      [tenants, cols, entries, Report.round2(entries * per_entry_ets / 1_048_576)]
    end
  )
)

# ---------------------------------------------------------------------------

Report.section("4. 32-byte tenant key and the 0x0478 suite (ADR-0003 OQ7)")

suites = [
  {"0x0478 (commit, no sign)", Vaults.Cached0478, Vaults.Uncached0478},
  {"0x0578 (commit + ECDSA P-384)", Vaults.Cached0578, Vaults.Uncached0578}
]

payloads = [
  {"16 B", payload_small},
  {"64 B (column)", payload_column},
  {"4 KiB (blob)", payload_blob}
]

rows =
  for {label, cached, _uncached} <- suites, {payload_label, payload} <- payloads do
    {:ok, ct} = cached.encrypt(payload, encryption_context: warm_ctx)

    enc_us =
      Report.micros(500, fn ->
        {:ok, _} = cached.encrypt(payload, encryption_context: warm_ctx)
        :ok
      end)

    dec_us =
      Report.micros(500, fn ->
        {:ok, _} = cached.decrypt(ct, encryption_context: warm_ctx)
        :ok
      end)

    [
      label,
      payload_label,
      byte_size(payload),
      byte_size(ct),
      byte_size(ct) - byte_size(payload),
      Report.round2(enc_us),
      Report.round2(dec_us)
    ]
  end

Report.table(
  ["suite", "payload", "plain B", "cipher B", "overhead B", "encrypt us", "decrypt us"],
  rows
)

# The 32-byte tenant master key: what minting, wrapping and unwrapping one
# actually costs, and how big the stored blob is.
{:ok, sample} =
  Encryptor.Envelope.provision(Vaults.Root, "merchant-measure",
    reference_subkey: reference_subkey,
    namespace: "bench-merchant"
  )

provision_us =
  Report.micros(50, fn ->
    {:ok, _} =
      Encryptor.Envelope.provision(Vaults.Root, "merchant-measure",
        reference_subkey: reference_subkey,
        namespace: "bench-merchant"
      )

    :ok
  end)

unwrap_us =
  Report.micros(200, fn ->
    {:ok, _} = Encryptor.Envelope.unwrap(Vaults.Root, sample)
    :ok
  end)

Report.row("tenant master key, declared bits", sample.bits)
Report.row("wrapped blob bytes", byte_size(sample.wrapped))
Report.row("tenant_ref chars", String.length(sample.tenant_ref))
Report.row("provision/3 us", Report.round2(provision_us))
Report.row("unwrap/2 us", Report.round2(unwrap_us))

# ---------------------------------------------------------------------------

Report.section("5. Addendum: Argon2id 64 MiB / 3 iterations (ADR-0003 amd B4, proposed)")

if Code.ensure_loaded?(Argon2.Base) do
  salt = :crypto.strong_rand_bytes(16)

  params = [
    {"floor of the bound: 32 MiB, 2 iter", %{memory_kib: 32_768, iterations: 2, parallelism: 1}},
    {"published floor-ish: 32 MiB, 3 iter", %{memory_kib: 32_768, iterations: 3, parallelism: 1}},
    {"B4 default: 64 MiB, 3 iter", %{memory_kib: 65_536, iterations: 3, parallelism: 1}},
    {"64 MiB, 1 iter", %{memory_kib: 65_536, iterations: 1, parallelism: 1}},
    {"128 MiB, 3 iter", %{memory_kib: 131_072, iterations: 3, parallelism: 1}}
  ]

  Report.table(
    ["parameters", "ms/hash", "hashes/sec (1 core)"],
    Enum.map(params, fn {label, p} ->
      us = Report.micros(5, fn -> _ = Encryptor.Kdf.slow_hash("a-column-value", salt, p) end)
      [label, Report.round2(us / 1000), Report.round2(1_000_000 / us)]
    end)
  )
else
  IO.puts("argon2_elixir not loaded - section skipped")
end

IO.puts("\ndone\n")
