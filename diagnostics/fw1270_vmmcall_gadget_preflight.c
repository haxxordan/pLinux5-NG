/* SPDX-License-Identifier: GPL-3.0-or-later
 * Read-only 12.70 preflight for a balanced kernel-context VMMCALL ROP path.
 * Checks live bytes and effective NX through the current kernel page tables.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define PMAP_STORE_OFF UINT64_C(0x3b6cfb8)
#define PRESENT UINT64_C(1)
#define LARGE UINT64_C(0x80)
#define NX (UINT64_C(1) << 63)
#define FRAME4K UINT64_C(0x000ffffffffff000)
#define FRAME2M UINT64_C(0x000fffffffe00000)
#define MAX_PA UINT64_C(0x1000000000)

extern unsigned long KERNEL_ADDRESS_DMAP_BASE;
extern int sceKernelGetMainSocId(void);

struct target {
  const char *name;
  uint64_t offset;
  const uint8_t *bytes;
  size_t length;
};

static const uint8_t balanced[] = {0x55, 0x57, 0xc3};
static const uint8_t vmmcall_tail[] = {0x0f, 0x01, 0xd9, 0x5d, 0xc3};
static const uint8_t pop_rdi[] = {0x5f, 0xc3};
static const struct target targets[] = {
    {"push_rbp_push_rdi_ret", 0xd22aa7, balanced, sizeof(balanced)},
    {"vmmcall_pop_rbp_ret", 0xc9dae9, vmmcall_tail, sizeof(vmmcall_tail)},
    {"pop_rdi_ret", 0x2a6784, pop_rdi, sizeof(pop_rdi)},
};

static int write_all(int fd, const char *bytes, size_t size)
{
  while (size) {
    ssize_t n = write(fd, bytes, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    bytes += (size_t)n;
    size -= (size_t)n;
  }
  return 0;
}

static int log_line(int fd, const char *line)
{
  return write_all(fd, line, strlen(line)) == 0 ? fsync(fd) : -1;
}

static int read_qword(uint64_t va, uint64_t *out)
{
  *out = 0;
  return kernel_copyout((intptr_t)va, out, sizeof(*out));
}

static int check_page(uint64_t pml4, uint64_t dmap, uint64_t va,
                      uint64_t *leaf, unsigned *leaf_mb)
{
  static const unsigned shifts[] = {39, 30, 21, 12};
  uint64_t table = pml4, nx = 0;
  for (unsigned i = 0; i < 4; ++i) {
    uint64_t entry = 0;
    if (read_qword(table + (((va >> shifts[i]) & 0x1ff) * 8), &entry) != 0 ||
        !(entry & PRESENT))
      return -1;
    nx |= entry & NX;
    if ((i == 1 || i == 2) && (entry & LARGE)) {
      *leaf = entry;
      *leaf_mb = i == 1 ? 1024 : 2;
      return nx ? -2 : 0;
    }
    if (i == 3) {
      *leaf = entry;
      *leaf_mb = 0;
      return nx ? -2 : 0;
    }
    uint64_t pa = entry & FRAME4K;
    if ((entry & LARGE) || !pa || pa >= MAX_PA)
      return -3;
    table = dmap + pa;
  }
  return -4;
}

int main(void)
{
  uint32_t fw = kernel_get_fw_version();
  int soc = sceKernelGetMainSocId();
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
  if ((fw & 0xffff0000U) != 0x12700000U || soc != 0x840f60 ||
      !text || data <= text || data - text != 0xd50000U ||
      (dmap >> 48) != 0xffffU || (dmap & 0x3fffffffU))
    return 1;

  struct timespec stamp = {0};
  if (clock_gettime(CLOCK_REALTIME, &stamp) != 0)
    return 2;
  char path[192], line[256];
  snprintf(path, sizeof(path),
           "/mnt/usb0/PS5-12.70-vmmcall-gadgets-%d-%ld-%ld.txt",
           (int)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return 3;
  snprintf(line, sizeof(line),
           "start,fw=0x%08x,soc=0x%x,text=0x%016" PRIx64
           ",dmap=0x%016" PRIx64 "\n", fw, soc, text, dmap);
  if (log_line(fd, line) != 0)
    goto fail;

  uint64_t pml4 = 0, cr3 = 0;
  if (read_qword(text + PMAP_STORE_OFF + 0x20, &pml4) != 0 ||
      read_qword(text + PMAP_STORE_OFF + 0x28, &cr3) != 0 ||
      !pml4 || !cr3 || (pml4 & 0xfff) || (cr3 & 0xfff) ||
      pml4 < cr3 || pml4 - cr3 != dmap || cr3 >= MAX_PA)
    goto fail;
  snprintf(line, sizeof(line), "pmap,pml4=0x%016" PRIx64 ",cr3=0x%016"
           PRIx64 "\n", pml4, cr3);
  if (log_line(fd, line) != 0)
    goto fail;

  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
    const struct target *t = &targets[i];
    uint8_t actual[8] = {0};
    uint64_t leaf = 0;
    unsigned leaf_mb = 0;
    int read = kernel_copyout((intptr_t)(text + t->offset), actual, t->length);
    int page = check_page(pml4, dmap, text + t->offset, &leaf, &leaf_mb);
    snprintf(line, sizeof(line),
             "target,index=%zu,name=%s,offset=0x%08" PRIx64
             ",read=%d,match=%d,page=%d,leaf_mb=%u,leaf=0x%016" PRIx64 "\n",
             i, t->name, t->offset, read,
             read == 0 && memcmp(actual, t->bytes, t->length) == 0,
             page, leaf_mb, leaf);
    if (log_line(fd, line) != 0 || read != 0 ||
        memcmp(actual, t->bytes, t->length) != 0 || page != 0)
      goto fail;
  }
  if (log_line(fd, "end,complete=1,targets=3\n") != 0)
    goto fail;
  close(fd);
  printf("12.70 VMMCALL gadget preflight: 3 bytes and mappings matched; log %s\n",
         path);
  return 0;

fail:
  log_line(fd, "end,complete=0\n");
  close(fd);
  printf("12.70 VMMCALL gadget preflight failed; log %s\n", path);
  return 4;
}
