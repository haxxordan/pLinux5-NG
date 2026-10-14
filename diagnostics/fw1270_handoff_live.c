/* SPDX-License-Identifier: GPL-3.0-or-later
 * Read-only live byte check for the pinned 12.70 handoff candidates.
 * Run only after a successful NPT clear on the same launch-model boot.
 * No patch, VMMCALL, rest-mode request, or Linux staging is performed.
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

#define FW_1270 0x12700000U
#define SOC_PHAT 0x840f60

extern unsigned long KERNEL_ADDRESS_DMAP_BASE;
extern int sceKernelGetMainSocId(void);

struct span {
  const char *name;
  int is_hv;
  uint64_t address;  /* text-relative for kernel, physical for HV */
  const unsigned char *expected;
  size_t length;
};

#define K(name, off, bytes) {name, 0, off, (const unsigned char *)bytes, sizeof(bytes) - 1}
#define H(name, pa, bytes) {name, 1, pa, (const unsigned char *)bytes, sizeof(bytes) - 1}

static const struct span spans[] = {
    K("hv_mp_startup_call", 0xc9dfb0ULL,
      "\x55\x48\x89\xe5\x53\x48\x89\xd3\x48\x89\xf1\xb8\x0f\x00\x00\x00"
      "\x89\xfa\x0f\x01\xd9\x5b\x5d\xc3"),
    K("smp_rendezvous", 0xb8fbc0ULL,
      "\x55\x48\x89\xe5\x49\x89\xc8\x48\x89\xd1\x48\x89\xf2\x48\x89\xfe"
      "\x48\x8b\x3d\x51\x06\x1a\x03\x5d\xe9\xa3\xfd\xff\xff"),
    K("rendezvous_setup", 0xb8faf7ULL, "\x41\xff\xd4"),
    K("rendezvous_action", 0xb8fb1cULL, "\x41\xff\xd7"),
    K("rendezvous_teardown", 0xb8fb41ULL, "\x41\xff\xd6"),
    H("dispatcher_entry", 0x62846a00ULL,
      "\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53"),
    H("vmcb_exitcode", 0x62846a31ULL,
      "\x48\x8b\x4f\x08\x48\x8b\x41\x70"),
    H("rax17_telemetry", 0x62846a6bULL,
      "\x48\x3d\x81\x00\x00\x00\x75\x0a\x48\x83\xb9\xf8\x05\x00\x00\x17\x74\x4c"),
    H("exit_jump_table", 0x62846af2ULL,
      "\x48\x8d\x05\x03\x47\x00\x00\x48\x63\x0c\x88\x48\x01\xc1\xff\xe1"),
    H("vmmcall_table_slot", 0x6284b3b0ULL, "\x79\xbf\xff\xff"),
    H("vmmcall_case", 0x62847175ULL,
      "\x49\x8b\x46\x08\x80\xb8\xcb\x04\x00\x00\x00\x0f\x84\x97\x03\x00\x00"),
    H("nested_command_dispatch", 0x628476b0ULL,
      "\x4c\x8b\x80\xf8\x05\x00\x00\x4d\x8d\x68\xfc\x49\x83\xfd\x1c"),
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

int main(void)
{
  uint32_t fw = kernel_get_fw_version();
  int soc = sceKernelGetMainSocId();
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
  if ((fw & 0xffff0000U) != FW_1270 || soc != SOC_PHAT ||
      !text || data <= text || data - text != 0xd50000U ||
      (dmap >> 48) != 0xffffU || (dmap & 0x3fffffffU) != 0 ||
      dmap > UINT64_MAX - 0x6284b3b0ULL - 32)
    return 1;

  struct timespec stamp = {0};
  if (clock_gettime(CLOCK_REALTIME, &stamp) != 0)
    return 2;
  char path[192], line[256];
  snprintf(path, sizeof(path),
           "/mnt/usb0/PS5-12.70-handoff-live-%d-%ld-%ld.txt",
           (int)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return 3;
  snprintf(line, sizeof(line),
           "start,fw=0x%08x,soc=0x%x,text=0x%016" PRIx64
           ",dmap=0x%016" PRIx64 ",spans=%zu\n",
           fw, soc, text, dmap, sizeof(spans) / sizeof(spans[0]));
  if (log_line(fd, line) != 0)
    goto io_error;

  for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); ++i) {
    const struct span *s = &spans[i];
    uint8_t actual[32] = {0};
    if (s->length > sizeof(actual))
      goto io_error;
    uint64_t source = (s->is_hv ? dmap : text) + s->address;
    snprintf(line, sizeof(line), "before,index=%zu,name=%s,source=0x%016" PRIx64
             ",length=%zu\n", i, s->name, source, s->length);
    if (log_line(fd, line) != 0)
      goto io_error;
    int rc = kernel_copyout((intptr_t)source, actual, s->length);
    if (rc != 0 || memcmp(actual, s->expected, s->length) != 0) {
      snprintf(line, sizeof(line), "stop,index=%zu,name=%s,result=%d,match=0\n",
               i, s->name, rc);
      log_line(fd, line);
      close(fd);
      return 4;
    }
    snprintf(line, sizeof(line), "after,index=%zu,name=%s,result=0,match=1\n",
             i, s->name);
    if (log_line(fd, line) != 0)
      goto io_error;
  }

  snprintf(line, sizeof(line), "end,complete=1,matches=%zu\n",
           sizeof(spans) / sizeof(spans[0]));
  if (log_line(fd, line) != 0)
    goto io_error;
  close(fd);
  printf("12.70 handoff live preflight: %zu spans matched; log %s\n",
         sizeof(spans) / sizeof(spans[0]), path);
  return 0;

io_error:
  log_line(fd, "stop,stage=io\n");
  close(fd);
  return 5;
}
