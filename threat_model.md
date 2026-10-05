# Threat model and limitations

| Attacker | Capability | Result |
|---|---|---|
| A1 – unprivileged local user | edits files they own | detected by `check` / `watch` |
| A2 – root, but **no** kernel tampering | edits/deletes/truncates the log, rewrites baseline | edits, deletions, re-ordering → hash-chain failure; baseline edit → trailer failure; a *fully re-forged* consistent log → **kernel cross-check mismatch**; tail truncation → noted by `verify-log` (kernel holds newer events) |
| A3 – kernel-level attacker | patches kernel/driver memory, or unloads the module | **not defended**; unloading resets the chain (seq restarts at 1) which shows up as mismatches/"not retained" for old records, but a skilled attacker can hide this |

Known limitations
* Chain-only verification cannot see **tail truncation**; only the kernel anchor can (as a warning, because heartbeats and other writers also advance the kernel counter).
* The kernel ring keeps the last `ring_size` events; older records show *not-retained* (they remain chain-verified in user space).
* The baseline is only as trustworthy as the moment it was created: create it on a clean system and keep a copy on read-only/offline media.
* inotify does not report writes through `mmap`, other mount namespaces, or `/proc`/`/sys`; schedule periodic `check` runs and rely on the initial scan after restarts.
* A file changed and restored between two scans is invisible to `check` (but visible in `watch`).
* `--quick` trusts mtime, which a root attacker can forge (test `compare_detects_same_size_modification_with_forged_mtime`). Use full hashing for security audits.
* SHA-256 is collision-resistant; the design assumes the hash function is not broken.
