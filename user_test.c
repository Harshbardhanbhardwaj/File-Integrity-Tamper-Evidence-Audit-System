/* user_test.c - exercises every entry point of /dev/fiaudit (run as root after insmod).
 *   gcc -Wall -O2 -o user_test user_test.c && sudo ./user_test
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fiaudit_ioctl.h"

static int failures;
#define CHECK(c) do { if (!(c)) { printf("  FAIL: %s (line %d, errno=%s)\n", #c, __LINE__, strerror(errno)); failures++; } else printf("  ok:   %s\n", #c); } while (0)

static void hex(const unsigned char *b, char *out) { for (int i = 0; i < FIA_HASH_LEN; i++) sprintf(out + 2 * i, "%02x", b[i]); }

int main(void)
{
	int fd = open("/dev/" FIA_DEVICE_NAME, O_RDWR);
	if (fd < 0) { perror("open /dev/fiaudit (is the module loaded? are you root?)"); return 2; }

	struct fia_stats s0, s1;
	CHECK(ioctl(fd, FIA_IOC_GET_STATS, &s0) == 0);
	printf("  total=%llu capacity=%u\n", (unsigned long long)s0.total, s0.capacity);

	/* 1. submit through ioctl */
	struct fia_event ev; memset(&ev, 0, sizeof ev);
	ev.type = FIA_EV_MODIFY; strcpy(ev.path, "/etc/passwd");
	CHECK(ioctl(fd, FIA_IOC_SUBMIT, &ev) == 0);
	CHECK(ev.seq == s0.total + 1);
	CHECK(ev.pid == (unsigned)getpid());
	unsigned char c1[FIA_HASH_LEN]; memcpy(c1, ev.chain, sizeof c1);

	/* 2. submit through write() */
	struct fia_event w; memset(&w, 0, sizeof w);
	w.type = FIA_EV_CREATE; strcpy(w.path, "/tmp/new");
	CHECK(write(fd, &w, sizeof w) == (ssize_t)sizeof w);
	CHECK(write(fd, &w, 10) < 0 && errno == EINVAL);        /* wrong size rejected */

	/* 3. invalid type rejected */
	w.type = 999;
	CHECK(ioctl(fd, FIA_IOC_SUBMIT, &w) < 0 && errno == EINVAL);

	/* 4. stats advanced by exactly 2 */
	CHECK(ioctl(fd, FIA_IOC_GET_STATS, &s1) == 0);
	CHECK(s1.total == s0.total + 2);
	CHECK(memcmp(s1.head, s0.head, FIA_HASH_LEN) != 0);

	/* 5. verify ioctl: correct, wrong, not retained */
	struct fia_verify v = { .seq = ev.seq };
	memcpy(v.chain, c1, FIA_HASH_LEN);
	CHECK(ioctl(fd, FIA_IOC_VERIFY, &v) == 0);
	v.chain[0] ^= 1;
	CHECK(ioctl(fd, FIA_IOC_VERIFY, &v) < 0 && errno == EBADMSG);
	v.seq = s1.total + 1000;
	CHECK(ioctl(fd, FIA_IOC_VERIFY, &v) < 0 && errno == ENOENT);

	/* 6. read(): last two events, in order, chain matches what submit returned */
	int fd2 = open("/dev/" FIA_DEVICE_NAME, O_RDWR | O_NONBLOCK);
	struct fia_event buf[2048];
	ssize_t n = read(fd2, buf, sizeof buf);
	CHECK(n > 0 && n % sizeof(struct fia_event) == 0);
	size_t cnt = n / sizeof(struct fia_event);
	CHECK(buf[cnt - 2].seq == ev.seq && !memcmp(buf[cnt - 2].chain, c1, FIA_HASH_LEN));
	CHECK(strcmp(buf[cnt - 1].path, "/tmp/new") == 0);
	CHECK(read(fd2, buf, sizeof buf) < 0 && errno == EAGAIN);  /* drained, non-blocking */

	/* 7. poll(): not readable now, readable after a new event */
	struct pollfd p = { .fd = fd2, .events = POLLIN };
	CHECK(poll(&p, 1, 0) == 0);
	w.type = FIA_EV_DELETE; strcpy(w.path, "/tmp/x");
	CHECK(write(fd, &w, sizeof w) == (ssize_t)sizeof w);
	CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));

	/* 8. unknown ioctl */
	CHECK(ioctl(fd, _IO('Z', 9)) < 0 && errno == ENOTTY);

	char h[65]; hex(s1.head, h);
	printf("  chain head after test: %s\n", h);
	close(fd); close(fd2);
	printf(failures ? "RESULT: %d FAILURE(S)\n" : "RESULT: all checks passed\n", failures);
	return failures != 0;
}
