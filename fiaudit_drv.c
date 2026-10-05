// SPDX-License-Identifier: GPL-2.0
/*
 * fiaudit_drv.c - "File Integrity Audit" character device driver.
 *
 * Role in the system
 * ------------------
 * The user-space daemon (fiaudit) detects file changes and appends them to a
 * hash-chained log file.  A privileged attacker can edit that file, so the
 * daemon ALSO submits every event to this driver.  The driver keeps a
 * tamper-evident chain in KERNEL memory:
 *
 *      chain[n] = SHA256(chain[n-1] || seq || ts || type || pid || path)
 *
 * The daemon stores (seq, chain[n]) in each log record, so later the log can
 * be cross-checked against kernel memory (FIA_IOC_VERIFY).
 *
 * Kernel concepts demonstrated
 *   - alloc_chrdev_region / cdev / class / device_create
 *   - file_operations: open, release, read, write, poll, unlocked_ioctl
 *   - mutex locking, wait queues, poll(2) support
 *   - copy_to_user / copy_from_user, ioctl numbers, capability check
 *   - kernel crypto API (shash / SHA-256)
 *   - delayed work (heartbeat), module parameters, /proc entry
 *   - resource cleanup with goto-unwinding
 *
 * Intended target: Linux 5.15 .. 6.x (uses LINUX_VERSION_CODE guards).
 * NOTE: kernel APIs drift between versions; if the build fails on your
 * kernel, see docs/stage5_testing.md ("Driver porting notes").
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/capability.h>
#include <linux/version.h>
#include <crypto/hash.h>

#include "fiaudit_ioctl.h"

#define DRV_NAME "fiaudit"

static unsigned int ring_size = 1024;
module_param(ring_size, uint, 0444);
MODULE_PARM_DESC(ring_size, "Number of events retained in the ring (default 1024)");

static unsigned int heartbeat_sec;
module_param(heartbeat_sec, uint, 0644);
MODULE_PARM_DESC(heartbeat_sec, "Insert a HEARTBEAT event every N seconds (0 = off)");

/* ------------------------------------------------------------------ */
/* Driver state                                                        */
/* ------------------------------------------------------------------ */
struct fia_dev {
	dev_t                  devt;
	struct cdev            cdev;
	struct class          *cls;
	struct device         *dev;

	struct mutex           lock;      /* protects everything below       */
	struct fia_event      *ring;      /* ring_size events                */
	u64                    next_seq;  /* seq of the NEXT event (from 1)  */
	u8                     head[FIA_HASH_LEN];

	wait_queue_head_t      wq;        /* readers wait here               */
	struct crypto_shash   *tfm;
	struct shash_desc     *desc;
	struct delayed_work    hb_work;
	struct proc_dir_entry *proc;
};

static struct fia_dev *g_dev;

/* ------------------------------------------------------------------ */
/* Core: append one event to the chain (caller holds dev->lock)        */
/* ------------------------------------------------------------------ */
static int fia_compute_chain(struct fia_dev *d, const struct fia_event *ev,
			     u8 *out)
{
	struct shash_desc *desc = d->desc;
	int ret;

	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, d->head, FIA_HASH_LEN);
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&ev->seq, sizeof(ev->seq));
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&ev->ts_ns, sizeof(ev->ts_ns));
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&ev->type, sizeof(ev->type));
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&ev->pid, sizeof(ev->pid));
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)ev->path, FIA_PATH_MAX);
	if (!ret)
		ret = crypto_shash_final(desc, out);
	return ret;
}

/* in: ev->type, ev->path.  out: all fields filled. */
static int fia_append_locked(struct fia_dev *d, struct fia_event *ev)
{
	u8 newhash[FIA_HASH_LEN];
	int ret;

	if (ev->type >= FIA_EV_MAX)
		return -EINVAL;

	ev->path[FIA_PATH_MAX - 1] = '\0';          /* force termination  */
	ev->seq   = d->next_seq;
	ev->ts_ns = ktime_get_real_ns();
	ev->pid   = current->tgid;

	ret = fia_compute_chain(d, ev, newhash);
	if (ret)
		return ret;

	memcpy(ev->chain, newhash, FIA_HASH_LEN);
	memcpy(d->head, newhash, FIA_HASH_LEN);
	d->ring[ev->seq % ring_size] = *ev;         /* overwrite oldest   */
	d->next_seq++;
	return 0;
}

static int fia_append(struct fia_dev *d, struct fia_event *ev)
{
	int ret;

	mutex_lock(&d->lock);
	ret = fia_append_locked(d, ev);
	mutex_unlock(&d->lock);
	if (!ret)
		wake_up_interruptible(&d->wq);
	return ret;
}

static u64 fia_oldest_locked(const struct fia_dev *d)
{
	u64 total = d->next_seq - 1;

	return (total > ring_size) ? total - ring_size + 1 : 1;
}

/* ------------------------------------------------------------------ */
/* file_operations                                                     */
/* ------------------------------------------------------------------ */
struct fia_file {
	u64 cursor;                 /* next seq this reader wants          */
};

static int fia_open(struct inode *inode, struct file *filp)
{
	struct fia_dev *d = container_of(inode->i_cdev, struct fia_dev, cdev);
	struct fia_file *f = kzalloc(sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	mutex_lock(&d->lock);
	f->cursor = fia_oldest_locked(d);   /* new readers start at oldest */
	mutex_unlock(&d->lock);
	filp->private_data = f;
	return 0;
}

static int fia_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static bool fia_has_data(struct fia_dev *d, struct fia_file *f)
{
	bool r;

	mutex_lock(&d->lock);
	r = f->cursor < d->next_seq;
	mutex_unlock(&d->lock);
	return r;
}

/* read(): returns whole struct fia_event records, non-destructive. */
static ssize_t fia_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct fia_dev *d = g_dev;
	struct fia_file *f = filp->private_data;
	size_t done = 0;
	int ret;

	if (count < sizeof(struct fia_event))
		return -EINVAL;

	while (!fia_has_data(d, f)) {
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(d->wq, fia_has_data(d, f));
		if (ret)
			return -ERESTARTSYS;
	}

	mutex_lock(&d->lock);
	if (f->cursor < fia_oldest_locked(d))       /* reader fell behind  */
		f->cursor = fia_oldest_locked(d);

	while (f->cursor < d->next_seq &&
	       count - done >= sizeof(struct fia_event)) {
		struct fia_event *src = &d->ring[f->cursor % ring_size];

		if (copy_to_user(buf + done, src, sizeof(*src))) {
			mutex_unlock(&d->lock);
			return done ? (ssize_t)done : -EFAULT;
		}
		done += sizeof(*src);
		f->cursor++;
	}
	mutex_unlock(&d->lock);
	return done;
}

/* write(): submit exactly one struct fia_event (type + path). */
static ssize_t fia_write(struct file *filp, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct fia_event ev;
	int ret;

	if (count != sizeof(ev))
		return -EINVAL;
	if (copy_from_user(&ev, buf, sizeof(ev)))
		return -EFAULT;
	ret = fia_append(g_dev, &ev);
	return ret ? ret : (ssize_t)count;
}

static __poll_t fia_poll(struct file *filp, poll_table *wait)
{
	struct fia_dev *d = g_dev;
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;      /* always writable    */

	poll_wait(filp, &d->wq, wait);
	if (fia_has_data(d, filp->private_data))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

static long fia_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct fia_dev *d = g_dev;
	void __user *uarg = (void __user *)arg;
	long ret = 0;

	if (_IOC_TYPE(cmd) != FIA_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case FIA_IOC_GET_STATS: {
		struct fia_stats st;

		memset(&st, 0, sizeof(st));
		mutex_lock(&d->lock);
		st.total      = d->next_seq - 1;
		st.oldest_seq = fia_oldest_locked(d);
		st.capacity   = ring_size;
		memcpy(st.head, d->head, FIA_HASH_LEN);
		mutex_unlock(&d->lock);
		if (copy_to_user(uarg, &st, sizeof(st)))
			ret = -EFAULT;
		break;
	}
	case FIA_IOC_SUBMIT: {
		struct fia_event ev;

		if (copy_from_user(&ev, uarg, sizeof(ev)))
			return -EFAULT;
		ret = fia_append(d, &ev);
		if (!ret && copy_to_user(uarg, &ev, sizeof(ev)))
			ret = -EFAULT;
		break;
	}
	case FIA_IOC_VERIFY: {
		struct fia_verify v;

		if (copy_from_user(&v, uarg, sizeof(v)))
			return -EFAULT;
		mutex_lock(&d->lock);
		if (v.seq == 0 || v.seq >= d->next_seq ||
		    v.seq < fia_oldest_locked(d))
			ret = -ENOENT;
		else if (memcmp(d->ring[v.seq % ring_size].chain, v.chain,
				FIA_HASH_LEN))
			ret = -EBADMSG;
		mutex_unlock(&d->lock);
		break;
	}
	case FIA_IOC_RESET:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		mutex_lock(&d->lock);
		memset(d->ring, 0, sizeof(*d->ring) * ring_size);
		memset(d->head, 0, FIA_HASH_LEN);
		d->next_seq = 1;
		mutex_unlock(&d->lock);
		break;
	default:
		ret = -ENOTTY;
	}
	return ret;
}

static const struct file_operations fia_fops = {
	.owner          = THIS_MODULE,
	.open           = fia_open,
	.release        = fia_release,
	.read           = fia_read,
	.write          = fia_write,
	.poll           = fia_poll,
	.unlocked_ioctl = fia_ioctl,
	.compat_ioctl   = fia_ioctl,
	.llseek         = no_llseek,
};

/* ------------------------------------------------------------------ */
/* Heartbeat (delayed work) and /proc                                  */
/* ------------------------------------------------------------------ */
static void fia_heartbeat(struct work_struct *w)
{
	struct fia_dev *d = container_of(to_delayed_work(w), struct fia_dev, hb_work);
	struct fia_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = FIA_EV_HEARTBEAT;
	strscpy(ev.path, "kernel-heartbeat", sizeof(ev.path));
	fia_append(d, &ev);

	if (heartbeat_sec)
		schedule_delayed_work(&d->hb_work, heartbeat_sec * HZ);
}

static int fia_proc_show(struct seq_file *m, void *v)
{
	struct fia_dev *d = g_dev;
	int i;

	mutex_lock(&d->lock);
	seq_printf(m, "total_events: %llu\n", d->next_seq - 1);
	seq_printf(m, "oldest_seq:   %llu\n", fia_oldest_locked(d));
	seq_printf(m, "ring_size:    %u\n", ring_size);
	seq_printf(m, "heartbeat:    %u s\n", heartbeat_sec);
	seq_puts(m, "chain_head:   ");
	for (i = 0; i < FIA_HASH_LEN; i++)
		seq_printf(m, "%02x", d->head[i]);
	seq_putc(m, '\n');
	mutex_unlock(&d->lock);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Module init / exit                                                  */
/* ------------------------------------------------------------------ */
static int __init fia_init(void)
{
	struct fia_dev *d;
	int ret;

	if (ring_size < 16 || ring_size > 65536)
		return -EINVAL;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	mutex_init(&d->lock);
	init_waitqueue_head(&d->wq);
	d->next_seq = 1;

	d->ring = kcalloc(ring_size, sizeof(*d->ring), GFP_KERNEL);
	if (!d->ring) {
		ret = -ENOMEM;
		goto err_free;
	}

	d->tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(d->tfm)) {
		ret = PTR_ERR(d->tfm);
		goto err_ring;
	}
	d->desc = kzalloc(sizeof(*d->desc) + crypto_shash_descsize(d->tfm),
			  GFP_KERNEL);
	if (!d->desc) {
		ret = -ENOMEM;
		goto err_tfm;
	}
	d->desc->tfm = d->tfm;

	ret = alloc_chrdev_region(&d->devt, 0, 1, DRV_NAME);
	if (ret)
		goto err_desc;

	cdev_init(&d->cdev, &fia_fops);
	d->cdev.owner = THIS_MODULE;
	ret = cdev_add(&d->cdev, d->devt, 1);
	if (ret)
		goto err_region;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	d->cls = class_create(DRV_NAME);
#else
	d->cls = class_create(THIS_MODULE, DRV_NAME);
#endif
	if (IS_ERR(d->cls)) {
		ret = PTR_ERR(d->cls);
		goto err_cdev;
	}

	d->dev = device_create(d->cls, NULL, d->devt, NULL, DRV_NAME);
	if (IS_ERR(d->dev)) {
		ret = PTR_ERR(d->dev);
		goto err_class;
	}

	g_dev = d;
	d->proc = proc_create_single(DRV_NAME, 0444, NULL, fia_proc_show);

	INIT_DELAYED_WORK(&d->hb_work, fia_heartbeat);
	if (heartbeat_sec)
		schedule_delayed_work(&d->hb_work, heartbeat_sec * HZ);

	pr_info(DRV_NAME ": loaded, major=%d ring=%u heartbeat=%us\n",
		MAJOR(d->devt), ring_size, heartbeat_sec);
	return 0;

err_class:
	class_destroy(d->cls);
err_cdev:
	cdev_del(&d->cdev);
err_region:
	unregister_chrdev_region(d->devt, 1);
err_desc:
	kfree(d->desc);
err_tfm:
	crypto_free_shash(d->tfm);
err_ring:
	kfree(d->ring);
err_free:
	kfree(d);
	return ret;
}

static void __exit fia_exit(void)
{
	struct fia_dev *d = g_dev;

	cancel_delayed_work_sync(&d->hb_work);
	if (d->proc)
		proc_remove(d->proc);
	device_destroy(d->cls, d->devt);
	class_destroy(d->cls);
	cdev_del(&d->cdev);
	unregister_chrdev_region(d->devt, 1);
	kfree(d->desc);
	crypto_free_shash(d->tfm);
	kfree(d->ring);
	kfree(d);
	g_dev = NULL;
	pr_info(DRV_NAME ": unloaded\n");
}

module_init(fia_init);
module_exit(fia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student - File Integrity & Tamper-Evidence Audit System");
MODULE_DESCRIPTION("Tamper-evident kernel-side audit chain for fiaudit");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("pre: sha256_generic");
