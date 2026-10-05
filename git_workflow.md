# Git workflow and branching strategy

```
main ─────────────────────────────────────────────●──────── (merge at Stage 6, tag v1.0)
 └─ develop ──●────●────●────●────●────●───────────┘
      ├ stage1-introduction   (docs)             tag stage1
      ├ stage2-requirements   (PRD)              tag stage2
      ├ stage3-design         (UML, skeleton)    tag stage3
      ├ stage4-prototype      (core code)        tag stage4
      ├ stage5-testing        (tests, fixes)     tag stage5
      └ stage6-final          (polish, report)   tag stage6
```
Setup: `scripts/git_setup.sh` (creates the branches). Then, for each stage:
```bash
git switch stage4-prototype
# ... work, small commits ...
git switch develop && git merge --no-ff stage4-prototype && git tag -a stage4 -m "Stage 4 prototype"
```
Feature work inside a stage may use short-lived branches (`feat/watcher-debounce`).

## Commit conventions
`type(scope): summary` – types: `feat fix docs test refactor perf build chore`.
Examples:
* `docs(stage2): add PRD with FR/NFR traceability`
* `feat(scanner): parallel hashing with thread pool`
* `fix(exclude): match component patterns relative to root`
* `perf(sha256): add SHA-NI path with CPUID dispatch`
* `feat(driver): add poll() and FIA_IOC_VERIFY`
* `test(log): detect swapped records`

Rules: one logical change per commit; build + tests green before merging to `develop`;
never commit binaries (`.gitignore`); every stage ends with a tag and an updated `progress_log.md`.

> Commit as you actually work – your history is evidence of your own continuous progress.
