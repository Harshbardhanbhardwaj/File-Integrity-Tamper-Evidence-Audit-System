# File Integrity & Tamper-Evidence Audit System (`fiaudit`)

Individual project – **Linux · Device Drivers · System Programming · C++17**

`fiaudit` records a trusted baseline of a directory tree, detects every change (live via
`inotify`, or on demand), and keeps a **tamper-evident audit trail**: a SHA-256 hash-chained
log file *plus* an independent chain held in kernel memory by a custom character-device
driver (`/dev/fiaudit`).

## Quick start (no root, no kernel module needed)
```bash
make                      # builds bin/fiaudit  (g++ >= 9, make)
make test                 # 39 unit tests
make integration          # 20 end-to-end CLI checks
scripts/demo.sh           # guided demo: baseline -> intrusion -> log -> log forgery detected
```
```bash
bin/fiaudit init  /etc --baseline /tmp/etc.base --log /tmp/audit.log --exclude '*.cache'
bin/fiaudit check --baseline /tmp/etc.base                 # exit 0 clean / 1 changes
bin/fiaudit watch --baseline /tmp/etc.base --log /tmp/audit.log   # live; Ctrl-C to stop; SIGHUP reloads baseline
bin/fiaudit verify-log --log /tmp/audit.log                # hash chain (+ kernel cross-check)
bin/fiaudit show-log   --log /tmp/audit.log --tail 20
```
`bin/fiaudit help` lists every option.

## With the kernel driver (needs a Linux VM, root, linux-headers)
```bash
sudo apt install build-essential linux-headers-$(uname -r)
sudo scripts/test_driver.sh     # build + load + test + cross-check + unload
sudo scripts/load_driver.sh     # leave it loaded; fiaudit then uses /dev/fiaudit automatically
```
> The driver source is complete but was **not compiled in the environment that produced this
> archive** (no kernel headers there). Build it in your VM and fix any API drift using
> `docs/driver_guide.md` / `docs/stage5_testing.md` §7. Everything user-space is built and tested.

## Repository layout
```
driver/      fiaudit_drv.c (kernel module), fiaudit_ioctl.h (shared ABI), user_test.c, Makefile
include/fiaudit/  headers: sha256, util, baseline, scanner, audit_log, device, watcher, thread_pool
src/         implementations + main.cpp (CLI)
tests/       unit tests (own mini framework), integration_test.sh
scripts/     demo.sh, load/unload/test_driver.sh, git_setup.sh, fiaudit.service (systemd)
docs/        stage1..stage6 documents, UML (PlantUML + Mermaid), threat model, driver guide,
             git workflow, progress log, presentation outline, training-topic mapping,
             evidence/ (real test, sanitizer, benchmark and demo output)
```

## The six stages -> documents
| Stage | Document |
|---|---|
| 1 Introduction | `docs/stage1_introduction.md` |
| 2 Requirements & plan (PRD) | `docs/stage2_prd.md` |
| 3 Design & architecture, UML, Git, environment | `docs/stage3_design.md`, `docs/uml/`, `docs/git_workflow.md` |
| 4 Prototype | `docs/stage4_prototype.md` |
| 5 Testing & improvement | `docs/stage5_testing.md`, `docs/evidence/` |
| 6 Final report & presentation | `docs/stage6_final_report.md`, `docs/presentation_outline.md` |
| Progress tracking | `docs/progress_log.md` |

## Git
```bash
scripts/git_setup.sh     # creates main/develop/stageN branches (then commit your own work)
```

## Before you submit – make it yours
1. Put your name in the docs and the module's `MODULE_AUTHOR`.
2. Build and run the driver tests in your VM; save output in `docs/evidence/`.
3. Read the code until you can explain every file (see likely questions in `docs/presentation_outline.md`).
4. Make your own commits per stage and fill in `docs/progress_log.md` with real dates.
5. Update `docs/training_topic_mapping.md` to match your actual 20-day syllabus.

## License
Kernel module: GPL-2.0. User space: MIT-style, educational use.
