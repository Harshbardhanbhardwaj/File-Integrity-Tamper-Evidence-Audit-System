# Kernel driver guide (`driver/`)

## Build and load (use a VM!)
```bash
sudo apt install build-essential linux-headers-$(uname -r)
cd driver && make                         # -> fiaudit.ko
sudo scripts/load_driver.sh 1024 0        # ring_size, heartbeat_sec
ls -l /dev/fiaudit ; cat /proc/fiaudit ; dmesg | tail
sudo scripts/test_driver.sh               # builds, loads, runs user_test + CLI cross-check, unloads
sudo scripts/unload_driver.sh
```
The heartbeat is chosen at load time (`sudo insmod fiaudit.ko heartbeat_sec=5`); reload the module to change it.

## Entry points
| Call | Behaviour |
|---|---|
| `open` | allocates a per-file cursor starting at the oldest retained event |
| `write(struct fia_event)` | submit an event (exactly 312 bytes, else `EINVAL`) |
| `ioctl(FIA_IOC_SUBMIT)` | submit and receive seq/ts/pid/chain |
| `read` | returns whole events from the cursor, non-destructive; blocks (or `EAGAIN` with `O_NONBLOCK`) |
| `poll` | readable when events newer than the cursor exist |
| `ioctl(FIA_IOC_GET_STATS)` | total, oldest retained seq, capacity, chain head |
| `ioctl(FIA_IOC_VERIFY)` | 0 match / `ENOENT` not retained / `EBADMSG` mismatch |
| `ioctl(FIA_IOC_RESET)` | clears chain; needs `CAP_SYS_ADMIN` |

## Using it from fiaudit
`fiaudit init|watch|check --log L` automatically uses `/dev/fiaudit` when present
(`--require-device` makes it mandatory; `--device none` disables; `--device sim` uses the in-memory model).
`fiaudit verify-log --log L` cross-checks every record against kernel memory.
Run the daemon as root, or `chmod 660 /dev/fiaudit` and add a group via udev.

## Debugging
`dmesg -w`, `cat /proc/fiaudit`, `strace -e trace=openat,ioctl`, `sudo insmod fiaudit.ko ring_size=64`,
dynamic debug (`pr_debug`), `CONFIG_DEBUG_KMEMLEAK`, `CONFIG_PROVE_LOCKING` in a debug kernel.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| `Required key not available` on insmod | Secure Boot; disable or sign the module |
| `Unknown symbol crypto_*` / ENOENT for sha256 | `sudo modprobe sha256_generic` |
| compile error about `class_create` / `no_llseek` | kernel API drift, see `stage5_testing.md` §7 |
| `/dev/fiaudit` missing | udev not running; `mknod /dev/fiaudit c $(awk '$2=="fiaudit"{print $1}' /proc/devices) 0` |
| `Permission denied` | run as root or fix device mode |
