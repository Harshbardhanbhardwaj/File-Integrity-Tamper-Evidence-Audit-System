/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fiaudit_ioctl.h - user/kernel ABI for the File Integrity Audit driver.
 *
 * Included by BOTH the kernel module (driver/fiaudit_drv.c) and the C++
 * user-space code (src/device.cpp).  Keep it plain C, fixed-width types only.
 */
#ifndef FIAUDIT_IOCTL_H
#define FIAUDIT_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define FIA_DEVICE_NAME "fiaudit"
#define FIA_PATH_MAX    256
#define FIA_HASH_LEN    32          /* SHA-256 */

/* Event types - numeric values are part of the ABI. */
enum fia_event_type {
	FIA_EV_HEARTBEAT = 0,
	FIA_EV_CREATE    = 1,
	FIA_EV_MODIFY    = 2,
	FIA_EV_DELETE    = 3,
	FIA_EV_ATTRIB    = 4,
	FIA_EV_MOVE      = 5,
	FIA_EV_SCAN      = 6,
	FIA_EV_TAMPER    = 7,
	FIA_EV_MAX
};

/*
 * One audit event.  Size = 312 bytes (multiple of 8, no implicit padding).
 *  - On submit (write() / FIA_IOC_SUBMIT) the caller fills 'type' and 'path'.
 *  - The driver fills 'seq', 'ts_ns', 'pid' and 'chain'.
 *
 * chain[n] = SHA256( chain[n-1] || seq || ts_ns || type || pid || path[256] )
 * (integers in host byte order, chain[0-th predecessor] = 32 zero bytes)
 */
struct fia_event {
	__u64 seq;
	__u64 ts_ns;
	__u32 type;
	__u32 pid;
	char  path[FIA_PATH_MAX];
	__u8  chain[FIA_HASH_LEN];
};

struct fia_stats {
	__u64 total;          /* events ever accepted (== last seq)          */
	__u64 oldest_seq;     /* oldest event still retained in the ring     */
	__u32 capacity;       /* ring capacity (events)                      */
	__u32 reserved;
	__u8  head[FIA_HASH_LEN];   /* current chain head                    */
};

struct fia_verify {
	__u64 seq;
	__u8  chain[FIA_HASH_LEN];
};

#define FIA_IOC_MAGIC      'F'
#define FIA_IOC_GET_STATS  _IOR(FIA_IOC_MAGIC, 1, struct fia_stats)
#define FIA_IOC_SUBMIT     _IOWR(FIA_IOC_MAGIC, 2, struct fia_event)
/* returns 0 = match, -ENOENT = seq not retained, -EBADMSG = mismatch */
#define FIA_IOC_VERIFY     _IOW(FIA_IOC_MAGIC, 3, struct fia_verify)
#define FIA_IOC_RESET      _IO(FIA_IOC_MAGIC, 4)   /* needs CAP_SYS_ADMIN */

#endif /* FIAUDIT_IOCTL_H */
