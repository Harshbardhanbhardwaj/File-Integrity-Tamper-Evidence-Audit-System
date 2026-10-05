# Stage 1 – Project Introduction

**Project title:** File Integrity & Tamper-Evidence Audit System ("fiaudit")
**Domains covered:** Linux system programming · Linux device drivers · C++17 · Computer architecture · Hardware/software interaction

---

## 1. Project idea and objective

*fiaudit* answers two questions about a Linux machine:

1. **"Did any important file change, and exactly how?"** – it records a trusted
   *baseline* (SHA-256, size, mode, owner of every file in a directory tree) and then
   detects additions, deletions, content changes, permission changes and symlink
   re-targeting, both on demand (`fiaudit check`) and in real time (`fiaudit watch`, built
   on Linux `inotify`).
2. **"Can I still trust the record of what changed?"** – an intruder who gets
   administrator rights will first try to erase their traces from the log. fiaudit therefore
   makes its own audit trail **tamper-evident**:
   * every log record is cryptographically chained to the previous one (hash chain);
   * every event is also sent to a **kernel module (character device `/dev/fiaudit`)**
     that keeps an independent SHA-256 chain **in kernel memory**. Each log record stores the
     kernel's `(seq, chain)` value, so the log can be cross-checked against the kernel later.

**Objective:** build a complete, professional-quality system that shows the full Linux
software stack – from a device driver in the kernel, through system calls, up to a
multi-threaded C++ application – and run it through a real software-engineering process
(requirements → design → implementation → testing → delivery).

## 2. Problem to be solved

| Problem | Why it matters |
|---|---|
| Configuration files, binaries and scripts can be silently modified (malware, misconfiguration, insider). | Changes are often discovered weeks later, if ever. |
| Ordinary log files can be edited or truncated by whoever has the privileges to attack the system. | A log that can be rewritten proves nothing. |
| Existing tools (AIDE, Tripwire, auditd) are large black boxes. | A student project should expose and explain every mechanism. |

## 3. Scope

**In scope**
* Baseline creation for a directory tree (regular files + symlinks), with exclusion patterns.
* One-shot audit and real-time monitoring (recursive inotify, debouncing, multi-threaded hashing).
* Hash-chained, append-only audit log with verification.
* Linux kernel character-device driver (`fiaudit.ko`) with `read/write/poll/ioctl`, a `/proc` entry,
  SHA-256 via the kernel crypto API, and a heartbeat work item.
* C++ user-space device abstraction (`IAuditSink`) with a kernel implementation, a software
  model (for testing without root) and a null implementation.
* Unit, integration, sanitizer and (driver) system tests; full documentation and UML.

**Out of scope** (documented as future work)
* Network/remote log shipping, GUI, e-mail alerts.
* Defence against an attacker who can already modify kernel memory (see `threat_model.md`).
* Windows/macOS support (Linux-specific APIs are used on purpose).

## 4. Expected outcome and applications

*Deliverables:* a working CLI (`bin/fiaudit`), the kernel module, a test-suite (39 unit tests,
20 integration checks), UML diagrams, a project report and presentation material.

*Applications:* host-based intrusion detection for servers (watch `/etc`, `/usr/bin`,
`/boot`), integrity checking of deployed software, compliance evidence (PCI-DSS 11.5 /
ISO 27001 style *file-integrity monitoring*), forensics (reliable timeline of changes), and
teaching material for Linux internals.

## 5. How the project demonstrates the training topics

See `training_topic_mapping.md` for the complete table. In short: **Linux** (processes,
signals, files, permissions, inotify/epoll, systemd, shell scripts, Makefiles) ·
**C++** (RAII, move semantics, templates, STL, `std::filesystem`, threads, polymorphism,
exceptions) · **Computer architecture** (endianness, alignment/ABI, page cache and I/O
buffering, SIMD/SHA-NI with CPUID dispatch, memory ordering) · **Hardware ↔ software**
(user/kernel boundary, system calls, `/dev` nodes, ioctl, kernel crypto, interrupts-vs-polling
discussion).

## 6. Roadmap to Stage 2

Write the Project Requirements Document (functional / non-functional requirements,
modules, deliverables) and the development plan with a timeline.
