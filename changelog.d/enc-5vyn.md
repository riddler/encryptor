### **Breaking**

- A vault now refuses on decrypt, as `:decrypt_failed`, a per-call context key the message's stored context lacks; a key `:required_context` names is checked as before. A host whose stored messages were written without a key its readers now pass sets the new `:legacy_context` option to `:accept` (default `:refuse`) while re-encrypting those pre-context ciphertexts, then sets it back (ADR-0004 Amendment C).
