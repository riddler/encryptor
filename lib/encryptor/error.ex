defmodule Encryptor.Error do
  @moduledoc """
  The one error struct this package returns, and the closed vocabulary of
  reasons it carries.

  Every non-bang entry point returns `{:ok, value}` or
  `{:error, %Encryptor.Error{}}`, and every bang variant raises this same
  struct. There is no second error shape, no bare atom, and no error tuple
  with a different arity depending on which layer failed.

  ## The four fields

    * `:reason` - this package's own stable, matchable term. The complete set
      is `t:reason/0`, and it is closed: it is extended by an ADR, never by a
      call site inventing a near-miss.
    * `:vault` - the vault module the operation ran against.
    * `:operation` - `:encrypt`, `:decrypt`, `:rekey`, or `:start`.
    * `:engine` - the underlying error term, unchanged, or `nil`.

  The split between `:reason` and `:engine` is the point. Consumers match on
  `:reason`, which this package owns and versions. Operators read `:engine` in
  a log line when they need to know which keyring rejected what. Terms from
  the engine - or from a provider's own stack, an `Ecto` changeset or an
  `ExAws` tuple - are *carried* in `:engine`, never translated away and never
  promoted into `:reason`. That is what keeps `t:reason/0` an enumeration a
  `case` can be written against.

  ## The oracle rule

  **Every decrypt-side failure that depends on the message collapses to
  `:decrypt_failed`.** A wrong key, a failed authentication tag, an encryption
  context mismatch, a required key absent from the message, and a commitment
  policy rejection are indistinguishable in `:reason`. The detail lives in
  `:engine`, for logs only.

  Distinguishable decrypt failures are a decryption oracle, and the caller
  cannot act differently on the distinctions anyway. `decrypt_failed/3` is the
  collapse point: the decrypt path builds its message-dependent failures
  through it rather than by assembling a struct by hand.

  Failures that depend only on caller-supplied arguments stay distinct,
  because they are not an oracle and the caller needs them: an unresolvable
  selector, a reserved context key, a required context key the *caller*
  omitted, a provider that could not answer at all. Provider resolution is
  carved out of the collapse in both directions - it happens before any
  ciphertext is examined, and reporting an unreachable key store as data
  corruption sends an operator looking for the wrong thing at three in the
  morning.

  ## Messages never carry key-shaped values

  `Exception.message/1` renders `:reason` only, and only the parts of it that
  are safe to print. It never renders `:engine`, and it never renders the
  detail of `{:invalid_key_descriptor, detail}` or `{:invalid_config, key,
  detail}`, either of which can hold key material. Plaintext, data keys, and
  wrapping key material never reach a message, a log line, or a failure
  report.

  Records: ADR-0001 decision 10, ADR-0002 decision 6, ADR-0004 decision 8.
  """

  @typedoc """
  A key selector, as ADR-0004 decision 3 fixes it: a non-empty `String.t()` in
  a `:tenant` vault, and the atom `:default` in a `:single` one.
  """
  @type selector :: String.t() | :default

  @typedoc "The vault operation an error arose from."
  @type operation :: :encrypt | :decrypt | :rekey | :start

  @typedoc """
  The complete reason vocabulary.

  Assembled from the accepted records: ADR-0001 decision 10 fixes the first
  seven, ADR-0002 decision 6 adds four for key resolution, and ADR-0004
  decision 8 adds three for the encryption context. ADR-0005 adds none - a
  rotation misconfiguration is an `{:invalid_config, key, detail}`.
  """
  @type reason ::
          :decrypt_failed
          | {:vault_not_started, module()}
          | {:missing_config, [atom()]}
          | {:invalid_config, atom(), term()}
          | {:unknown_key, selector()}
          | {:encryption_context_conflict, String.t()}
          | {:reserved_context_key, String.t()}
          | {:key_unavailable, selector()}
          | {:invalid_key_descriptor, term()}
          | {:provider_not_started, module()}
          | {:missing_optional_dependency, atom()}
          | {:missing_required_context_keys, [String.t()]}
          | {:invalid_context_value, String.t() | :count | :too_large}
          | {:invalid_selector, term()}

  @type t :: %__MODULE__{
          reason: reason(),
          vault: module() | nil,
          operation: operation() | nil,
          engine: term() | nil
        }

  defexception [:reason, :vault, :operation, :engine]

  @doc """
  Builds the collapsed failure for a decrypt-side condition that depends on
  the message.

  The engine's term - or the vault's own term, when a check ran above the
  engine - is carried in `:engine` unchanged. It is never inspected to pick a
  reason, and it never reaches the rendered message.

      iex> error = Encryptor.Error.decrypt_failed(MyApp.Vault, :decrypt, {:encryption_context_mismatch, "column"})
      iex> error.reason
      :decrypt_failed
      iex> error.engine
      {:encryption_context_mismatch, "column"}

  A `rekey/2` failure on its decrypt half carries `:rekey`, because the
  operation is what the caller asked for:

      iex> Encryptor.Error.decrypt_failed(MyApp.Vault, :rekey, :key_mismatch).operation
      :rekey
  """
  @spec decrypt_failed(module(), operation(), term()) :: t()
  def decrypt_failed(vault, operation, engine)
      when operation in [:decrypt, :rekey] do
    %__MODULE__{
      reason: :decrypt_failed,
      vault: vault,
      operation: operation,
      engine: engine
    }
  end

  @doc """
  Renders an error for a human.

  The rendered string carries the reason and where it happened, never the
  `:engine` term and never a value that could be key-shaped.

      iex> Encryptor.Error.message(%Encryptor.Error{reason: :decrypt_failed, vault: MyApp.Vault, operation: :decrypt})
      "decryption failed (MyApp.Vault, decrypt)"

      iex> Encryptor.Error.message(%Encryptor.Error{reason: {:missing_optional_dependency, :ecto}})
      "missing optional dependency :ecto"
  """
  @impl Exception
  @spec message(t()) :: String.t()
  def message(%__MODULE__{reason: reason} = error) do
    describe(reason) <> where(error)
  end

  @spec describe(reason()) :: String.t()
  defp describe(:decrypt_failed), do: "decryption failed"

  defp describe({:vault_not_started, module}),
    do: "vault #{inspect(module)} is not started"

  defp describe({:missing_config, path}),
    do: "missing configuration at #{inspect(path)}"

  # The detail is deliberately not rendered: a rotation or provider key can
  # hold material, and this string reaches logs.
  defp describe({:invalid_config, key, _detail}),
    do: "invalid configuration for #{inspect(key)}"

  defp describe({:unknown_key, selector}),
    do: "no key for selector #{inspect(selector)}"

  defp describe({:encryption_context_conflict, key}),
    do: "caller-supplied encryption context conflicts on key #{inspect(key)}"

  defp describe({:reserved_context_key, key}),
    do: "encryption context key #{inspect(key)} is reserved"

  defp describe({:key_unavailable, selector}),
    do: "key for selector #{inspect(selector)} is unavailable"

  # Same reason as :invalid_config - a descriptor carries key material.
  defp describe({:invalid_key_descriptor, _detail}),
    do: "the provider returned a key descriptor this vault cannot use"

  defp describe({:provider_not_started, module}),
    do: "provider #{inspect(module)} is not started"

  defp describe({:missing_optional_dependency, dep}),
    do: "missing optional dependency #{inspect(dep)}"

  defp describe({:missing_required_context_keys, keys}),
    do: "missing required encryption context keys #{inspect(keys)}"

  defp describe({:invalid_context_value, :count}),
    do: "the encryption context has too many entries"

  defp describe({:invalid_context_value, :too_large}),
    do: "the encryption context is too large"

  defp describe({:invalid_context_value, key}),
    do: "invalid encryption context value for #{inspect(key)}"

  defp describe({:invalid_selector, selector}),
    do: "invalid selector #{inspect(selector)} for this vault's context profile"

  @spec where(t()) :: String.t()
  defp where(%__MODULE__{vault: nil, operation: nil}), do: ""
  defp where(%__MODULE__{vault: nil, operation: operation}), do: " (#{operation})"
  defp where(%__MODULE__{vault: vault, operation: nil}), do: " (#{inspect(vault)})"

  defp where(%__MODULE__{vault: vault, operation: operation}),
    do: " (#{inspect(vault)}, #{operation})"
end
