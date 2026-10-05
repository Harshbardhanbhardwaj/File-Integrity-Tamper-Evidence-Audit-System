# Stage 2 – Project Requirements Document (PRD) & Development Plan

**Product:** File Integrity & Tamper-Evidence Audit System (fiaudit) – version 1.0
**Author:** *(student name)*  **Status:** Approved baseline for implementation

## 1. Purpose and users
Detect and prove unauthorised changes to files on a Linux host. Users: system administrators,
security engineers, auditors.

## 2. Functional requirements

| ID | Requirement | Priority | Module | Verified by |
|----|-------------|----------|--------|-------------|
| FR-1 | Create a baseline of a directory tree storing path, type, size, mtime, mode, uid, gid and SHA-256 for every regular file and symlink. | Must | Scanner, Baseline | `baseline_build_and_roundtrip` |
| FR-2 | Support exclusion patterns (`*.tmp`, `.git`, absolute prefixes) persisted in the baseline. | Must | ExcludeSet | `exclude_set_rules`, integration |
| FR-3 | One-shot check reporting ADDED / MODIFIED / DELETED / META / TYPE changes; exit code 0 = clean, 1 = changes. | Must | Scanner, CLI | `compare_*`, integration |
| FR-4 | `--json` output for machine consumption. | Should | CLI | integration |
| FR-5 | `--quick` mode trusting size+mtime (documented trade-off). | Could | Scanner | `compare_detects_same_size…` |
| FR-6 | Real-time monitoring of the whole tree (including directories created later) using inotify. | Must | Watcher | `watcher_reports_live_changes` |
| FR-7 | Coalesce bursts of events (debounce) and avoid re-reporting an unchanged state; report "restored to baseline". | Should | Watcher | same |
| FR-8 | Recover from inotify queue overflow with a full rescan; run an initial scan at start-up. | Should | Watcher | code review / manual |
| FR-9 | Reload the baseline on `SIGHUP`; stop cleanly on `SIGINT`/`SIGTERM`. | Should | Watcher, CLI | integration |
| FR-10 | Append every event to a hash-chained audit log (seq, time, type, path, detail, kernel seq/hash, prev, hash). | Must | AuditLog | `log_*` |
| FR-11 | `verify-log` detects modified, deleted, re-ordered and half-written records. | Must | AuditLog | `log_detects_*` |
| FR-12 | Log must stay consistent with several threads and several processes writing. | Must | AuditLog | `log_concurrent…`, `log_two_writers…` |
| FR-13 | Baseline file protects itself with an integrity trailer; tampering is rejected. | Must | Baseline | `baseline_detects_own_tampering` |
| FR-14 | Kernel driver `/dev/fiaudit`: accept events (`write`, `ioctl SUBMIT`), keep a SHA-256 chain and a ring buffer, serve `read`, `poll`, `GET_STATS`, `VERIFY`, privileged `RESET`. | Must | Driver | `driver/user_test.c` |
| FR-15 | Each log record carries the kernel (seq, chain); `verify-log` cross-checks them and flags mismatches. | Must | Auditor, KernelSink | `kernel_anchor_catches…` |
| FR-16 | Works without the driver (graceful fall-back) and without root (software model `--device sim`). | Must | IAuditSink | integration |
| FR-17 | `/proc/fiaudit` shows driver statistics; module parameters `ring_size`, `heartbeat_sec`. | Should | Driver | driver guide |
| FR-18 | Refuse to extend a log that already fails verification (unless `--force`). | Should | CLI | integration |

## 3. Non-functional requirements

| ID | Requirement | Target / measurement |
|----|-------------|----------------------|
| NFR-1 Performance | Hashing throughput comparable to `sha256sum`. | ≥ 900 MB/s on SHA-NI hardware (measured 0.54 s / 512 MiB, see `evidence/benchmark.txt`). |
| NFR-2 Scalability | Multi-threaded hashing; bounded memory (64 KiB read buffer per thread). | thread pool, streaming reads |
| NFR-3 Reliability | No lost/duplicated log lines under concurrency; `fsync` after every record; atomic baseline replacement (tmp + rename). | tests `log_concurrent…` |
| NFR-4 Security | Does not follow symlinks (`O_NOFOLLOW`), `fstat` after open, regular files only; log is append-only (`O_APPEND`) + `flock`; kernel `CAP_SYS_ADMIN` for reset. | code review, threat model |
| NFR-5 Portability | Linux ≥ 5.15, x86-64 (portable C++ fallback for other CPUs); C++17, GCC ≥ 9 / Clang. | build on Ubuntu 24.04 / GCC 13 |
| NFR-6 Maintainability | Warnings-clean build (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion`), modular headers, RAII, documented ABI. | build log |
| NFR-7 Testability | Hardware abstraction (`IAuditSink`) so the whole system is testable without root; sanitizers clean (ASan, UBSan, TSan). | `evidence/sanitizers.txt` |
| NFR-8 Usability | Single binary, `--help`, meaningful exit codes (0/1/2/64), human-readable log viewer. | integration |
| NFR-9 Observability | Timestamped stderr logging, `--verbose`, `/proc/fiaudit`, kernel `pr_info`. | manual |

## 4. Scope, modules and features

| Module | Responsibility | Files |
|---|---|---|
| M1 Core utilities | RAII fd, errors, escaping, glob/exclude, logging | `util.*` |
| M2 Crypto | SHA-256 (portable + SHA-NI) | `sha256.*` |
| M3 Scanner & Baseline | tree walk, parallel hashing, baseline file, comparison | `scanner.*`, `baseline.*`, `thread_pool.hpp` |
| M4 Audit log | hash chain, verify, concurrency-safe append | `audit_log.*` |
| M5 Device layer | `IAuditSink`: kernel, model, null | `device.*` |
| M6 Monitor | inotify/epoll watcher, debounce, signals | `watcher.*` |
| M7 CLI | commands, option parsing, exit codes | `main.cpp` |
| M8 Kernel driver | char device, crypto chain, poll, ioctl, /proc | `driver/*` |
| M9 Tests & tooling | unit/integration/driver tests, scripts, systemd unit | `tests/`, `scripts/` |

## 5. Deliverables
Source code (user space + driver) · Makefiles · UML diagrams (class, sequence, state,
component) · PRD, design, test report, final report · Git repository with history and tags ·
demo script and presentation outline · evidence (test logs, benchmark, demo output).

## 6. Assumptions and constraints
Linux host, GCC ≥ 9, `linux-headers` installed for the driver, root privileges only for
loading the module. inotify watch limit (`fs.inotify.max_user_watches`) bounds tree size.

## 7. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Kernel API changes between versions | driver fails to build | `LINUX_VERSION_CODE` guards, porting notes in `driver_guide.md` |
| Kernel bugs can crash the machine | data loss | develop in a VM, snapshot before `insmod` |
| inotify misses events (queue overflow, mmap writes) | missed change | overflow → full rescan; periodic `check` recommended |
| Attacker with kernel write access | defeats anchor | documented in `threat_model.md` |

## 8. Development plan and timeline
The training lasts 20 days; the project is developed in six stages alongside it
(dates to be filled in by the student in `progress_log.md`).

| Stage | Suggested window | Main work | Exit criteria | Git tag |
|---|---|---|---|---|
| 1 Introduction | Day 1–3 | idea, problem, scope | `stage1_introduction.md` presented | `stage1` |
| 2 Requirements & plan | Day 3–6 | PRD, plan, risks | PRD approved | `stage2` |
| 3 Design & architecture | Day 6–9 | architecture, UML, data structures, env + Git | diagrams + skeleton builds | `stage3` |
| 4 Prototype | Day 9–13 | SHA-256, scanner, baseline, `init/check`; driver skeleton | demo of `init/check` | `stage4` |
| 5 Test & integrate | Day 13–17 | log chain, watcher, driver ↔ daemon, tests, sanitizers, optimisation | all tests green | `stage5` |
| 6 Final & presentation | Day 17–20 | polish, docs, report, demo | final presentation | `stage6` |

## 9. Requirement traceability
Every FR/NFR above names the test or evidence that verifies it; the final report
(`stage6_final_report.md`) contains the compliance summary.
