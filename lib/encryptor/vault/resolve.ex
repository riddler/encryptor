defmodule Encryptor.Vault.Resolve do
  @moduledoc false

  # The three steps every entry point takes identically, in one place.
  #
  # `encrypt/2` and `decrypt/2` differ in which provider callback they ask and
  # in what they do with the answer. They do **not** differ in how a selector
  # is typed against the vault's profile, in how a provider that answers
  # outside its contract is reported, or in how the four context layers are
  # composed - and the failure that each of those checks exists to catch is a
  # failure that has to be caught on both sides or it is not caught at all.
  #
  # A `:tenant` vault that refused `:default` at encrypt and accepted it at
  # decrypt would accept a read no write could have produced. A caller-supplied
  # `tenant_ref` refused on the way in and honoured on the way out would be a
  # second place to claim a tenant, which is exactly what ADR-0004 decision 4
  # removes. So these live here rather than once per path, and `rekey/2`
  # (`enc-gsd`) inherits them by calling the same three functions.
  #
  # `operation` is threaded through every function rather than inferred,
  # because `rekey/2`'s decrypt half reports `:rekey`: the operation is what
  # the caller asked for, not which half of it failed.

  alias Encryptor.Context
  alias Encryptor.Error
  alias Encryptor.Vault.Config
  alias Encryptor.Vault.Reference

  # ADR-0002 decision 6's provider vocabulary. A provider answering with one
  # of these is answering in contract, and its term is carried through
  # unchanged; anything else is a defect in the provider.
  @provider_reasons [
    :unknown_key,
    :key_unavailable,
    :invalid_key_descriptor,
    :provider_not_started,
    :missing_optional_dependency
  ]

  # ADR-0004 decision 3: the profile fixes the selector type, and both
  # refusals are caller-argument failures that depend on no ciphertext.
  #
  # An absent `:key` is `:default`, which is what makes the single-key vault's
  # "no per-call ceremony" ergonomics of ADR-0001 decision 4 true. A `:tenant`
  # vault therefore refuses an absent `:key` as `{:invalid_selector, :default}`,
  # which is the same refusal it gives for an explicit one: there is no shape
  # of the call in which a tenant vault reaches key material without a tenant.
  @doc false
  @spec selector(Config.t(), keyword(), Error.operation()) ::
          {:ok, Error.selector()} | {:error, Error.t()}
  def selector(%Config{context_profile: :single} = config, opts, operation) do
    case Keyword.get(opts, :key, :default) do
      :default -> {:ok, :default}
      other -> {:error, error(config, operation, {:invalid_selector, other})}
    end
  end

  def selector(%Config{context_profile: :tenant} = config, opts, operation) do
    case Keyword.get(opts, :key, :default) do
      selector when is_binary(selector) and selector != "" -> {:ok, selector}
      other -> {:error, error(config, operation, {:invalid_selector, other})}
    end
  end

  @doc false
  # The one key a write goes under.
  @spec encryption_key(Config.t(), Error.selector(), Error.operation()) ::
          {:ok, term()} | {:error, Error.t()}
  def encryption_key(config, selector, operation) do
    ask(config, operation, fn module ->
      module.encryption_key(config.provider_state, selector)
    end)
  end

  @doc false
  # Every key a stored message for this selector might have been written
  # under, newest first. This is `Encryptor.Vault.Keyring.build_all/3`'s
  # designed input, and dropping a name from what a provider answers here is
  # the crypto-shred mechanism (ADR-0002 decision 7).
  @spec decryption_keys(Config.t(), Error.selector(), Error.operation()) ::
          {:ok, term()} | {:error, Error.t()}
  def decryption_keys(config, selector, operation) do
    ask(config, operation, fn module ->
      module.decryption_keys(config.provider_state, selector)
    end)
  end

  # The provider is called on the caller's process, with the state frozen at
  # start, and it sees a selector and nothing else - no plaintext, no
  # ciphertext, no context, no configuration (ADR-0002 decision 1).
  @spec ask(Config.t(), Error.operation(), (module() -> term())) ::
          {:ok, term()} | {:error, Error.t()}
  defp ask(%Config{provider: {module, _opts}} = config, operation, callback) do
    case callback.(module) do
      {:ok, answer} ->
        {:ok, answer}

      {:error, reason} ->
        if provider_reason?(reason),
          do: {:error, error(config, operation, reason)},
          else: {:error, off_contract(config, operation, reason)}

      other ->
        {:error, off_contract(config, operation, other)}
    end
  end

  @spec provider_reason?(term()) :: boolean()
  defp provider_reason?(reason) when is_tuple(reason) and tuple_size(reason) == 2,
    do: elem(reason, 0) in @provider_reasons

  defp provider_reason?(_reason), do: false

  # A provider that answers outside its contract is a bug in the provider, not
  # in the caller, which is exactly what `{:invalid_key_descriptor, detail}`
  # means. The term itself goes in `:engine`, which is never rendered: a
  # provider's return can hold anything, including key material.
  @spec off_contract(Config.t(), Error.operation(), term()) :: Error.t()
  defp off_contract(config, operation, term) do
    error(config, operation, {:invalid_key_descriptor, :provider_off_contract}, term)
  end

  @doc false
  # The four layers, composed. At encrypt this is the context the message will
  # carry; at decrypt it is the context the reader claims the message carries,
  # and the two are built the same way on purpose - a reader that composed its
  # claim differently from the writer would disagree with correct messages.
  #
  # `reserved` is the top layer: the `encryptor-*` pairs this package sets on
  # its **own** messages, which today is `Encryptor.Envelope`'s wrapped-key
  # binding (ADR-0003 decision 4). It is a positional argument rather than an
  # option in `opts` on purpose. `opts` is the caller's keyword list, so a
  # reserved layer reachable through it would be a route for a host to write
  # under a prefix `Encryptor.Context` refuses it - which is the whole content
  # of `{:reserved_context_key, key}`. Nothing on the public vault surface
  # passes it; only the envelope does.
  @spec context(Config.t(), Error.selector(), keyword(), Error.operation(), Context.context()) ::
          {:ok, Context.context()} | {:error, Error.t()}
  def context(config, selector, opts, operation, reserved \\ %{}) do
    per_call = Keyword.get(opts, :encryption_context, %{})

    Context.compose(config, per_call,
      supplied: vault_supplied(config, selector),
      reserved: reserved,
      operation: operation
    )
  end

  # ADR-0004 decision 4: on a `:tenant` vault the pair is derived from the
  # `:key` selector rather than accepted from the caller, so the routing
  # argument and the context pair are incapable of disagreeing. A caller that
  # supplies `tenant_ref` or `tenant_id` is refused by `Encryptor.Context`,
  # which is where the reserved vocabulary lives.
  @spec vault_supplied(Config.t(), Error.selector()) :: Context.context()
  defp vault_supplied(%Config{context_profile: :tenant} = config, selector) do
    %{Context.tenant_ref_key() => Reference.derive(config.reference_subkey, selector)}
  end

  defp vault_supplied(%Config{context_profile: :single}, _selector), do: %{}

  @spec error(Config.t(), Error.operation(), Error.reason(), term()) :: Error.t()
  defp error(%Config{vault: vault}, operation, reason, engine \\ nil) do
    %Error{reason: reason, vault: vault, operation: operation, engine: engine}
  end
end
