# Presentation outline (≈ 15 min + demo)

1. **Title & problem** (1 min) – "Can you trust your logs after a break-in?"
2. **Objective & scope** (1) – FIM + tamper-evident audit trail (Stage 1)
3. **Requirements** (1.5) – top FR/NFR, traceability (Stage 2)
4. **Architecture** (2) – component diagram; user/kernel split; data flow (Stage 3)
5. **Design details** (2) – class diagram (`IAuditSink`), state machine of watcher, log record + hash chain, `fia_event` layout
6. **Kernel driver** (2) – file_operations, locking, wait queue/poll, crypto API, ioctl, /proc
7. **System programming** (1.5) – inotify+epoll+eventfd, signals, thread pool, `flock`/`fsync`
8. **Computer architecture** (1.5) – endianness, ABI/padding, SHA-NI dispatch, 5× speed-up chart, page cache
9. **Testing** (1.5) – 39 + 20 + driver tests, sanitizers, tamper scenarios table
10. **Live demo** (5–8) – see `stage6_final_report.md` §4
11. **Limitations & future work** (1) – threat model honesty, fanotify/TPM/eBPF
12. **Process evidence & Q&A** (1) – Git graph, progress log

## Likely questions – prepare answers
* Why can't an attacker just rewrite the log *and* the chain? (kernel anchor; limits in threat model)
* Why `O_APPEND` *and* `flock`? (atomic append vs. read-modify-write of the chain tail across processes)
* Why debounce? Why a thread pool? Why `eventfd` instead of doing work in the signal handler?
* What happens on inotify queue overflow? On root deletion? On module unload?
* Why mutex (not spinlock) in the driver? (process context, may sleep during SHA-256/copy_to_user)
* Why is `copy_from_user` needed? What if the user pointer is bad? (`-EFAULT`)
* How does the SHA-NI path work and how do you know it is correct? (CPUID, test vectors, cross-check)
* How does `read()` differ from a pipe? (non-destructive, per-open cursor)
