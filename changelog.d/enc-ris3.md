### Fixed

- Under a shared suspension store, a `suspend/2` or `reinstate/2` that
  answered `{:suspension_store_unavailable, store}` on its five-second timeout
  is no longer performed seconds later with a second
  `[:encryptor, :suspension, :changed]` event, and a store whose `list/1`
  hangs no longer blocks every write behind it: a refresh gives the store five
  seconds.
