### **Breaking**

- A vault now refuses on decrypt and rekey, as `:decrypt_failed`, a message whose algorithm suite is neither its configured `:algorithm_suite_id` nor listed in the new `:accept_suites` option (default empty); a host whose stored messages use another suite lists that suite in `:accept_suites` while it re-encrypts them with `rekey/2`, then removes it (ADR-0001 Amendment D).
