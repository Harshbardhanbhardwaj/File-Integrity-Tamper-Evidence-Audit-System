# Stage 4 – Initial Implementation & Prototype

## 1. Prototype scope
The first working prototype delivers the *core pipeline* end-to-end:

`directory tree → parallel SHA-256 → baseline file → compare → report`

plus the kernel driver skeleton (`open/release/read/write`, ioctl numbers).

| Milestone | Content | Evidence |
|---|---|---|
| M4.1 | `Fd`, `SysError`, hex/escape helpers, `ExcludeSet` | `test_core.cpp` |
| M4.2 | SHA-256 verified with NIST vectors (`abc`, 448-bit message, 1 M × `a`) | `sha256_*` tests |
| M4.3 | `ThreadPool`, `make_record`, `list_files`, `build_baseline` | `baseline_build_and_roundtrip` |
| M4.4 | Baseline file with integrity trailer; `compare_with_baseline`, `classify` | `compare_*` tests |
| M4.5 | CLI `init` / `check` with exit codes | `tests/integration_test.sh` |
| M4.6 | Driver skeleton: `alloc_chrdev_region`, `cdev`, `class`, `device_create`, ioctl header | `driver/` |

## 2. Demonstration (initial functionality)
```
$ bin/fiaudit init /srv/site --baseline base --log log --exclude '*.tmp'
baseline written: base
  files: 3
$ echo hacked > /srv/site/conf/server.conf
$ bin/fiaudit check --baseline base
[MODIFIED] /srv/site/conf/server.conf  (size 10 -> 7)
scanned 3 files, 1 change(s), 0 error(s)          (exit code 1)
```
A complete scripted run is in `docs/evidence/demo_run.txt` (`scripts/demo.sh`).

## 3. Integration approach
Components were integrated progressively: each layer was unit-tested before the next was
built on top of it (crypto → scanner → baseline → CLI), and the *pure* `classify()`
function was written once and reused later by the watcher.

## 4. Development progress, issues and solutions

| # | Issue | Root cause | Solution |
|---|-------|-----------|----------|
| 1 | Design review: exclusion pattern `*.tmp` would exclude **everything** if the root directory itself were named `x.tmp`. | patterns were matched against every component of the *absolute* path | `ExcludeSet` takes the root and matches component patterns on the relative path; regression test in `exclude_set_rules`. |
| 2 | Filenames containing TAB/newline would corrupt the line-based baseline and log. | text format with TAB separators | percent-escaping (`pct_escape`), test with a hostile file name. |
| 3 | A crash while saving the baseline could leave a half-written file. | in-place write | write to `file.tmp.<pid>`, `fsync`, `rename()` (atomic). |
| 4 | Hashing a FIFO/device named like a file would block forever; a file could be swapped for a symlink between `lstat` and `open`. | TOCTOU / special files | `open(O_NOFOLLOW|O_NONBLOCK)`, then `fstat` and require `S_ISREG`. |
| 5 | Compiler warning `-Wformat-truncation` in `iso_time`. | buffer sized for the normal case only | larger buffer; build is now warning-free under `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`. |
| 6 | Unit test failed with garbage output for `s.stats()->head_hex`. | test bound `auto&&` to a member of a **temporary** `optional` (dangling reference) | keep the `optional` in a local variable. Lesson: lifetime of temporaries. |
| 7 | Integration test for baseline tampering did not trigger. | `sed` pattern assumed a 5-byte file | tamper with the `T` (timestamp) line instead. |

## 5. Next stage
Add the audit-log hash chain, the inotify watcher, the user↔kernel link, and the complete
test/benchmark campaign.
