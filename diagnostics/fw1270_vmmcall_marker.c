/* SPDX-License-Identifier: GPL-3.0-or-later
 * Bounded 12.70 VMMCALL root-mode entry marker, launch-model only.
 * Requires NPT clear on this boot. Patches one 4-byte HV jump-table slot,
 * runs one CPL3 VMMCALL, then restores the slot and the staged cave bytes.
 * The stub preserves flags, RAX and RDX, writes one kernel-cave marker, and
 * jumps to the original 12.70 VMMCALL case. It does not boot Linux.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define FW_1270 0x12700000U
#define SOC_PHAT 0x840f60
#define CAVE_PA UINT64_C(0x62806f00)
#define TABLE_PA UINT64_C(0x6284b1fc)
#define SLOT_PA UINT64_C(0x6284b3b0)
#define CASE_PA UINT64_C(0x62847175)
#define MARKER_OFF UINT64_C(0x2d29440)
#define MARKER UINT64_C(0x1270cafe4d41524b)
#define COMMAND UINT64_C(0x1000)
#define STUB_LEN 34U

_Static_assert((int64_t)CAVE_PA - (int64_t)TABLE_PA >= INT32_MIN &&
               (int64_t)CAVE_PA - (int64_t)TABLE_PA <= INT32_MAX,
               "jump-table redirect must fit rel32");
_Static_assert((int64_t)CASE_PA - (int64_t)(CAVE_PA + STUB_LEN) >= INT32_MIN &&
               (int64_t)CASE_PA - (int64_t)(CAVE_PA + STUB_LEN) <= INT32_MAX,
               "stub return must fit rel32");

extern unsigned long KERNEL_ADDRESS_DMAP_BASE;
extern int sceKernelGetMainSocId(void);

static sigjmp_buf recovery;
static volatile sig_atomic_t fault_signal;
static volatile sig_atomic_t fault_code;

static const uint8_t case_bytes[] = {
    0x49, 0x8b, 0x46, 0x08, 0x80, 0xb8, 0xcb, 0x04,
    0x00, 0x00, 0x00, 0x0f, 0x84, 0x97, 0x03, 0x00, 0x00};
static const uint8_t kernel_bytes[] = {
    0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x89, 0xd3,
    0x48, 0x89, 0xf1, 0xb8, 0x0f, 0x00, 0x00, 0x00,
    0x89, 0xfa, 0x0f, 0x01, 0xd9, 0x5b, 0x5d, 0xc3};
static const uint8_t slot_bytes[] = {0x79, 0xbf, 0xff, 0xff};

static void on_fault(int sig, siginfo_t *info, void *context)
{
  (void)context;
  fault_signal = sig;
  fault_code = info ? info->si_code : 0;
  siglongjmp(recovery, 1);
}

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

static int read_region(uint64_t va, void *dst, size_t len)
{
  return kernel_copyout((intptr_t)va, dst, len);
}

static int write_region(uint64_t va, const void *src, size_t len)
{
  return kernel_copyin(src, (intptr_t)va, len);
}

static int restore_region(uint64_t va, const void *original, size_t len)
{
  uint8_t now[STUB_LEN];
  if (len > sizeof(now))
    return -1;
  for (int attempt = 0; attempt < 3; ++attempt) {
    write_region(va, original, len);
    if (read_region(va, now, len) == 0 && memcmp(now, original, len) == 0)
      return 0;
  }
  return -1;
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
      dmap > UINT64_MAX - SLOT_PA - STUB_LEN ||
      text > UINT64_MAX - MARKER_OFF - sizeof(uint64_t))
    return 1;

  struct timespec stamp = {0};
  if (clock_gettime(CLOCK_REALTIME, &stamp) != 0)
    return 2;
  char path[192], line[256];
  snprintf(path, sizeof(path),
           "/mnt/usb0/PS5-12.70-vmmcall-marker-%d-%ld-%ld.txt",
           (int)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return 3;
  snprintf(line, sizeof(line),
           "start,fw=0x%08x,soc=0x%x,text=0x%016" PRIx64
           ",dmap=0x%016" PRIx64 ",table_pa=0x%08" PRIx64
           ",cave_pa=0x%08" PRIx64 ",command=0x%04" PRIx64 "\n",
           fw, soc, text, dmap, SLOT_PA, CAVE_PA, COMMAND);
  if (log_line(fd, line) != 0) {
    close(fd);
    return 4;
  }

  const uint64_t cave_va = dmap + CAVE_PA;
  const uint64_t slot_va = dmap + SLOT_PA;
  const uint64_t case_va = dmap + CASE_PA;
  const uint64_t marker_va = text + MARKER_OFF;
  uint8_t current[STUB_LEN] = {0};
  uint8_t original_cave[STUB_LEN] = {0};
  uint64_t original_marker = 0, observed_marker = 0;
  int cave_dirty = 0, slot_dirty = 0, call_made = 0;
  int table_restored = 1, cave_restored = 1, marker_restored = 1;
  int preflight = 0, patch_rc = 0, signal_number = 0, signal_code = 0;
  volatile uint64_t call_rax = COMMAND;

  if (log_line(fd, "before,stage=preflight\n") != 0)
    goto cleanup;
  if (read_region(text + 0xc9dfb0ULL, current, sizeof(kernel_bytes)) != 0 ||
      memcmp(current, kernel_bytes, sizeof(kernel_bytes)) != 0 ||
      read_region(case_va, current, sizeof(case_bytes)) != 0 ||
      memcmp(current, case_bytes, sizeof(case_bytes)) != 0 ||
      read_region(slot_va, current, sizeof(slot_bytes)) != 0 ||
      memcmp(current, slot_bytes, sizeof(slot_bytes)) != 0 ||
      read_region(cave_va, original_cave, sizeof(original_cave)) != 0 ||
      read_region(marker_va, &original_marker, sizeof(original_marker)) != 0 ||
      original_marker != 0)
    goto cleanup;
  for (size_t i = 0; i < sizeof(original_cave); ++i)
    if (original_cave[i] != 0xcc)
      goto cleanup;
  preflight = 1;
  if (log_line(fd, "after,stage=preflight,result=0,case=1,slot=1,cave_cc=1,marker_zero=1\n") != 0)
    goto cleanup;

  /* pushfq; push rax; push rdx; movabs rax, marker_va;
   * movabs rdx, MARKER; mov [rax],rdx; pop rdx; pop rax; popfq;
   * jmp original VMMCALL case. All changed guest-visible state is restored. */
  uint8_t stub[STUB_LEN] = {
      0x9c, 0x50, 0x52, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
      0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0,
      0x48, 0x89, 0x10, 0x5a, 0x58, 0x9d, 0xe9, 0, 0, 0, 0};
  uint64_t marker_value = MARKER;
  int32_t return_rel = (int32_t)((int64_t)CASE_PA - (int64_t)(CAVE_PA + STUB_LEN));
  int32_t slot_rel = (int32_t)((int64_t)CAVE_PA - (int64_t)TABLE_PA);
  memcpy(stub + 5, &marker_va, sizeof(marker_va));
  memcpy(stub + 15, &marker_value, sizeof(marker_value));
  memcpy(stub + 30, &return_rel, sizeof(return_rel));

  if (log_line(fd, "before,stage=stage-cave\n") != 0)
    goto cleanup;
  cave_dirty = 1;
  patch_rc = write_region(cave_va, stub, sizeof(stub));
  if (patch_rc != 0 || read_region(cave_va, current, sizeof(stub)) != 0 ||
      memcmp(current, stub, sizeof(stub)) != 0)
    goto cleanup;
  if (log_line(fd, "after,stage=stage-cave,result=0,readback=1\n") != 0)
    goto cleanup;

  if (log_line(fd, "before,stage=patch-slot\n") != 0)
    goto cleanup;
  slot_dirty = 1;
  patch_rc = write_region(slot_va, &slot_rel, sizeof(slot_rel));
  if (patch_rc != 0 || read_region(slot_va, current, sizeof(slot_rel)) != 0 ||
      memcmp(current, &slot_rel, sizeof(slot_rel)) != 0)
    goto cleanup;
  if (log_line(fd, "after,stage=patch-slot,result=0,readback=1\n") != 0)
    goto cleanup;

  struct sigaction sa = {0};
  sa.sa_sigaction = on_fault;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  if (log_line(fd, "before,stage=vmmcall\n") != 0)
    goto cleanup;
  call_made = 1;
  if (sigsetjmp(recovery, 1) == 0) {
    uint64_t rax = COMMAND;
    __asm__ volatile("vmmcall" : "+a"(rax) : : "memory");
    call_rax = rax;
  } else {
    signal_number = (int)fault_signal;
    signal_code = (int)fault_code;
  }

cleanup:
  /* The table must be restored before removing code from the cave. */
  if (slot_dirty) {
    log_line(fd, "before,stage=restore-slot\n");
    table_restored = restore_region(slot_va, slot_bytes, sizeof(slot_bytes)) == 0;
    snprintf(line, sizeof(line), "after,stage=restore-slot,result=%d\n",
             table_restored ? 0 : -1);
    log_line(fd, line);
  }
  if (call_made) {
    snprintf(line, sizeof(line),
             "after,stage=vmmcall,result=%s,sig=%d,code=%d,rax=0x%016" PRIx64 "\n",
             signal_number ? "signal" : "returned", signal_number,
             signal_code, (uint64_t)call_rax);
    log_line(fd, line);
  }
  if (call_made && table_restored &&
      read_region(marker_va, &observed_marker, sizeof(observed_marker)) == 0) {
    snprintf(line, sizeof(line), "observe,marker=0x%016" PRIx64 "\n",
             observed_marker);
    log_line(fd, line);
  }
  if (cave_dirty && table_restored) {
    cave_restored = restore_region(cave_va, original_cave,
                                   sizeof(original_cave)) == 0;
    snprintf(line, sizeof(line), "after,stage=restore-cave,result=%d\n",
             cave_restored ? 0 : -1);
    log_line(fd, line);
  }
  if (cave_dirty && !table_restored)
    cave_restored = 0; /* leave executable stub while slot may still point here */
  if (preflight && call_made && table_restored) {
    marker_restored = restore_region(marker_va, &original_marker,
                                     sizeof(original_marker)) == 0;
    snprintf(line, sizeof(line), "after,stage=restore-marker,result=%d\n",
             marker_restored ? 0 : -1);
    log_line(fd, line);
  }
  if (preflight && call_made && !table_restored)
    marker_restored = 0;
  int complete = preflight && call_made && table_restored && cave_restored &&
                 marker_restored && observed_marker == MARKER;
  snprintf(line, sizeof(line),
           "end,complete=%d,marker=%d,slot_restored=%d,cave_restored=%d,marker_restored=%d\n",
           complete, observed_marker == MARKER, table_restored,
           cave_restored, marker_restored);
  log_line(fd, line);
  close(fd);
  printf("12.70 VMMCALL marker: complete=%d, marker=%d, slot_restored=%d; log %s\n",
         complete, observed_marker == MARKER, table_restored, path);
  return complete ? 0 : 5;
}
