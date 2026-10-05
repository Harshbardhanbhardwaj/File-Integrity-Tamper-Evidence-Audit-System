# Stage 5 – Testing, Integration & Improvement

## 1. Test strategy

| Level | What | Tool | Count |
|---|---|---|---|
| Unit | SHA-256, utils, thread pool, baseline, scanner, log chain, device model | `bin/run_tests` (own mini framework) | 39 |
| Integration | in-process watcher with real inotify; Auditor ↔ sink ↔ log | same binary | included above |
| System (CLI) | init/check/watch/verify-log/show-log, signals, exit codes, tamper scenarios | `tests/integration_test.sh` | 20 checks |
| Driver | every entry point of `/dev/fiaudit` | `driver/user_test.c`, `scripts/test_driver.sh` | 25 checks |
| Robustness | AddressSanitizer + UBSan, ThreadSanitizer | `make asan`, `-fsanitize=thread` | whole suite |

## 2. Results (from this repository, GCC 13, Ubuntu 24.04)
* Unit tests: **39 run, 0 failed** (`evidence/unit_tests.txt`)
* CLI integration: **20 passed, 0 failed** (`evidence/integration_test.txt`)
* ASan+UBSan: **0 findings**; TSan: **0 warnings** (`evidence/sanitizers.txt`)
* Demo run: `evidence/demo_run.txt`

> **Honest status of the driver:** the sandbox used to produce this archive has no kernel
> headers, so `fiaudit_drv.c` could **not** be compiled or loaded there. The ABI header is
> compiled by the user-space code and `user_test.c` compiles cleanly; the driver's algorithm
> is mirrored by `MemorySink`, which is unit-tested. **You must build and run
> `scripts/test_driver.sh` in your own Linux VM and record the output as evidence**
> (instructions in `driver_guide.md`).

## 3. Security-relevant test scenarios
| Scenario | Expected | Test |
|---|---|---|
| edit a record's path | chain failure at that line | `log_detects_modified_record` |
| delete a record | sequence-gap failure | `log_detects_deleted_record` |
| swap two records | failure | `log_detects_swapped_records` |
| half-written last line | failure | `log_detects_partial_last_line` |
| tail truncation | chain alone cannot see it (documented) | `log_tail_truncation_is_NOT_detectable…` |
| whole log re-forged with a valid chain | kernel anchor mismatch | `kernel_anchor_catches_consistently_rewritten_log` |
| baseline edited | integrity trailer rejects it | `baseline_detects_own_tampering` |
| same-size edit with forged mtime | full hash catches it; `--quick` does not | `compare_detects_same_size…` |
| symlink re-targeted | MODIFIED | `symlinks_are_tracked_not_followed` |
| two writers / four threads | chain stays valid | `log_two_writers…`, `log_concurrent…` |

## 4. Debugging and fixes in this stage
* Dangling-reference test bug (see Stage 4 issue 6) found by the first full run.
* `Watcher` member order: `ThreadPool` is declared **last** so its destructor joins workers
  before the objects they use are destroyed.
* Signal handling: handlers only call `request_stop()/request_reload()` (an atomic store +
  `write()` to an `eventfd`), both async-signal-safe.
* Writing to a log whose tail was changed by another writer: `AuditLog` compares `st_size`
  with its expected size under `flock` and reloads the chain tail when different.

## 5. Performance improvement (computer-architecture work)
Dataset: 64 files × 8 MiB = 512 MiB, 1 CPU core (`evidence/benchmark.txt`)

| Variant | Time |
|---|---|
| `sha256sum` (coreutils, reference) | 0.46 s |
| fiaudit, portable C++ SHA-256 | 2.71 s |
| fiaudit, **SHA-NI path** (CPUID dispatch, `sha256rnds2/msg1/msg2`) | **0.54 s** (5× faster) |
| `check --quick` (metadata only) | 0.003 s |

Other optimisations: whole 64-byte blocks are hashed directly from the caller's buffer
(no copy), 64 KiB `read()` buffer per thread, `posix_fadvise(SEQUENTIAL)` to enlarge kernel
read-ahead, hashing fanned out over a thread pool (`--threads`). The SHA-NI and portable
paths are cross-checked by `sha256_hardware_and_software_paths_agree`.

## 6. Code-quality measures
Warning-free at `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`; RAII everywhere (no manual
`close`/`delete`); `const`-correct interfaces; exceptions for errors, exit codes at the CLI
boundary; interface-based design.

## 7. Driver porting notes
* `class_create(THIS_MODULE, name)` became `class_create(name)` in 6.4 (guarded).
* `no_llseek` may need replacing by `.llseek = noop_llseek` (or dropping it) on very recent kernels.
* `proc_create_single` needs ≥ 5.6-era procfs API (older: `proc_create` + `seq_file`).
* The SHA-256 algorithm must be available: `CONFIG_CRYPTO_SHA256=y/m` (`modprobe sha256_generic`).
* Secure Boot: unsigned modules are refused – disable Secure Boot in the VM or sign the module.

## 8. Roadmap to Stage 6
Run the driver tests in a VM, record screenshots/logs, finish documentation, rehearse the demo.
