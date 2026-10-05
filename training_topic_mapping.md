# Mapping of the 20-day training topics to the project

> Adjust the "Day/Topic" wording to your actual syllabus; the *where in the project* column
> shows concrete code you can point to during the presentation.

| Topic | Where it appears | Key files |
|---|---|---|
| **Linux basics, shell, permissions** | mode/uid/gid tracking, `chmod` detection, demo/integration shell scripts, exit codes | `scripts/*.sh`, `tests/integration_test.sh`, `scanner.cpp` |
| **File system & VFS** | `lstat`, `readlink`, directory walking, symlinks vs files, atomic `rename` | `scanner.cpp`, `baseline.cpp` |
| **Processes & signals** | `sigaction`, async-signal-safe handlers, SIGHUP reload, SIGTERM shutdown, exit status | `main.cpp`, `watcher.cpp` |
| **File I/O & system calls** | `open/read/write/pread/fsync/flock/fstat/posix_fadvise`, `O_APPEND`, `O_NOFOLLOW`, EINTR loops | `sha256.cpp`, `audit_log.cpp` |
| **I/O multiplexing** | `inotify`, `epoll`, `eventfd` | `watcher.cpp` |
| **Threads & synchronisation** | thread pool, mutex, condition variables, `std::future`, atomics, `flock` between processes | `thread_pool.hpp`, `audit_log.cpp` |
| **IPC / user↔kernel interface** | `/dev/fiaudit`, `ioctl`, `read/write/poll` | `device.cpp`, `driver/` |
| **Makefiles & build tools** | top-level Makefile, kbuild Makefile, sanitizers, dependency files | `Makefile`, `driver/Makefile` |
| **Debugging tools** | ASan/UBSan/TSan, `strace`, `dmesg`, `gdb` | `Makefile` (asan), `stage6_final_report.md` |
| **Device drivers** | char device registration, `file_operations`, `copy_to/from_user`, wait queues, poll, mutex, ioctl numbers, `capable()`, module params, `/proc`, workqueue, error unwinding | `driver/fiaudit_drv.c` |
| **Kernel crypto API** | `crypto_alloc_shash("sha256")` | `fiaudit_drv.c` |
| **C++: classes, RAII, move semantics** | `Fd` (move-only), `AuditLog`, `Baseline` | `util.hpp` |
| **C++: inheritance & polymorphism** | `IAuditSink` → `KernelSink`/`MemorySink`/`NullSink` | `device.hpp` |
| **C++: templates & STL** | `ThreadPool::submit` (`invoke_result_t`, `packaged_task`), `map`, `unordered_map`, `optional`, `string_view`, `filesystem` | `thread_pool.hpp`, `scanner.cpp` |
| **C++: exceptions & error handling** | `SysError` carries `errno`; exit codes at the boundary | `util.hpp`, `main.cpp` |
| **C++: smart pointers & ownership** | `unique_ptr<IAuditSink>`, `shared_ptr<const Baseline>` swapped on reload | `main.cpp`, `watcher.cpp` |
| **Data structures & algorithms** | ordered map, hash chain, ring buffer (kernel), glob matching with backtracking, debounce map | `baseline.hpp`, `util.cpp`, `driver` |
| **Computer architecture – data representation** | endianness: SHA-256 loads big-endian words explicitly, kernel chain uses host order (documented ABI); alignment/padding; `static_assert(sizeof==312)` | `sha256.cpp`, `fiaudit_ioctl.h`, `device.cpp` |
| **Computer architecture – CPU/ISA** | x86 SHA extensions, SIMD registers (`__m128i`), CPUID feature detection, runtime dispatch, function-level `target` attribute | `sha256.cpp` |
| **Computer architecture – memory hierarchy / OS** | page cache and read-ahead (`fadvise`), streaming 64 KiB buffer vs cache size, `thread_local` buffers, memory ordering of atomics | `sha256.cpp`, `watcher.hpp` |
| **Hardware ↔ software layers** | disk → block layer → VFS → inotify → daemon → device driver; user/kernel mode switch via syscalls; polling vs interrupt-driven wake-ups | `stage3_design.md` |
| **Security** | tamper evidence, TOCTOU defences, least privilege (`CAP_SYS_ADMIN`), systemd hardening | `threat_model.md`, `fiaudit.service` |
| **Software engineering** | PRD, UML, Git branching, tests, traceability | all of `docs/` |

## Suggested architecture experiments (extra credit)
1. Run `perf stat bin/fiaudit check` with and without `FIAUDIT_NO_SHANI=1`; compare instructions/cycle.
2. `strace -c bin/fiaudit check` – count syscalls; change the buffer from 64 KiB to 4 KiB and observe `read` calls.
3. `echo 3 > /proc/sys/vm/drop_caches` (root) and compare cold vs warm cache hashing time.
4. `hexdump -C` an event read from `/dev/fiaudit` and locate each field of `struct fia_event`.
