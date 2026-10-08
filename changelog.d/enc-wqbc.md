### Changed

- Requires `aws_encryption_sdk ~> 1.1`, whose message header follows the AWS Encryption SDK specification for required encryption context: a vault's required pairs (every `:scoped` vault's `scope_ref`, and the keys in `:required_context`) are authenticated and bound to the message but no longer stored in its header, and `Encryptor.Message.describe/1` no longer shows them. Messages written earlier still decrypt and rekey. An `aws_encryption_sdk` 1.0.x reader cannot read a message the new engine writes with required context, so upgrade every reader before any writer.
- Messages a vault writes now read in the AWS Encryption SDK for Python, and Python's messages read in a vault, on both suites and both context profiles.
