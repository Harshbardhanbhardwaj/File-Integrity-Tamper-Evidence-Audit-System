# Stage 6 – Final Report & Presentation Material

## 1. Final system
```
            +------------------ user space ------------------+
 inotify -> | Watcher -> ThreadPool -> Scanner/Sha256         |
            |    |                                            |
            |    v                                            |
            | Auditor -> AuditLog (hash chain file)           |
            |    |                                            |
            +----|--------------------------------------------+
                 | ioctl/write/read/poll
            +----v----- kernel space -----------------------+
            | /dev/fiaudit  (cdev, ring, SHA-256 chain)      |
            +------------------------------------------------+
```
Size: ≈ 3,800 lines of code (C++17 library + CLI ≈ 2,400 incl. headers, kernel module + ABI header + driver test ≈ 640, tests ≈ 710) plus scripts and documentation.

## 2. Requirement compliance
All *Must* and *Should* requirements of `stage2_prd.md` are implemented. Items verified
only by the driver tests (FR-14, FR-17) must be executed in your VM (see `driver_guide.md`).
`--quick` (FR-5) is implemented with the documented trade-off.

## 3. Results
* 39 unit + 20 CLI tests pass; sanitizers clean.
* Detects add/modify/delete/chmod/symlink retarget live and on demand.
* Detects log edits, deletions, re-ordering, half-writes, and full-log forgery (with kernel anchor).
* 512 MiB hashed in 0.54 s single-core (parity with coreutils).

## 4. Demonstration script (≈ 8 minutes)
1. `make && make test` (show green).
2. `sudo scripts/load_driver.sh`; `cat /proc/fiaudit`; `dmesg | tail`.
3. `scripts/demo.sh` (or `DEVICE=/dev/fiaudit scripts/demo.sh`) – narrate each step.
4. `strace -f -e trace=inotify_add_watch,epoll_wait,ioctl bin/fiaudit watch …` to show the system-call boundary.
5. Tamper with the log, run `verify-log` with the device → mismatch.
6. `sudo scripts/unload_driver.sh`.

## 5. Achievements
Full vertical slice (kernel driver → syscalls → multithreaded C++ app); defence-in-depth
tamper evidence; hardware-accelerated crypto with safe fallback; professional process
(PRD, UML, traceability, tests, sanitizers, Git workflow).

## 6. Limitations
See `threat_model.md`: kernel-level attacker, inotify blind spots (mmap, namespaces), baseline
trust-on-first-use, ring-buffer retention, no remote shipping, x86-64-only hardware path
(portable fallback elsewhere), driver validated against the 5.15–6.x API *by design* – you must
confirm on your kernel.

## 7. Future improvements
* `fanotify` (mount-wide, pre-access permission events) and eBPF for process attribution (who changed the file).
* Sign the log head with an HMAC/Ed25519 key kept in a TPM; periodic remote anchoring.
* Netlink/uevent notifications from the driver; sysfs attributes; DKMS packaging.
* ARMv8 crypto-extension path; AVX2 multi-buffer hashing.
* Incremental baseline updates (`fiaudit accept`), JSON-lines log export, Prometheus metrics.
* Kernel-side KUnit tests and `kselftest` integration.

## 8. Submission checklist
- [ ] Source + driver + Makefiles ✔ (this archive)
- [ ] UML diagrams (`docs/uml`, Mermaid in `stage3_design.md`)
- [ ] Git repository with stage tags (`scripts/git_setup.sh`, then your own commits)
- [ ] Project report (this file + stage docs; export to PDF if required: `pandoc docs/*.md -o report.pdf`)
- [ ] Driver test output from your VM added to `docs/evidence/`
- [ ] Presentation (`presentation_outline.md`)
