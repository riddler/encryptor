### **Breaking**

- **Breaking:** `Encryptor.Provider.GcpKms` answers a `Decrypt` that Cloud
  KMS refuses with HTTP 400 or 404 (an AAD mismatch, a key or version that is
  not there) as `{:invalid_key_descriptor, {:kms_refused, status}}` from
  `encryption_key/2` and `decryption_keys/2`, where it answered
  `{:key_unavailable, selector}`; an IAM denial, a throttle, a server error
  and a transport or token failure still answer `{:key_unavailable,
  selector}`. Match the new term wherever a caller handled a refused row as
  `:key_unavailable`, and stop retrying it.
