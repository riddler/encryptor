### Fixed

- A vault's suspended set is now a `:protected` ETS table that only the vault's own process writes, so a suspension is set or lifted only through `suspend/2`, `reinstate/2` or a shared store's refresh; any other process in the node that writes the table directly now raises `ArgumentError` from ETS, where it used to set or lift a suspension silently. Reads, and every answer the two verbs give, are unchanged.
