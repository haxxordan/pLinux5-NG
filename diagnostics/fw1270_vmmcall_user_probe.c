/* SPDX-License-Identifier: GPL-3.0-or-later
 * One user-mode VMMCALL with an out-of-range command on launch-model 12.70.
 * No HV or kernel patch. A signal is caught and recorded when possible.
 * This checks only whether a deliberate CPL3 VMMCALL returns or signals.
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

#define COMMAND UINT64_C(0x1000)

extern int sceKernelGetMainSocId(void);

static sigjmp_buf recovery;
static volatile sig_atomic_t fault_signal;
static volatile sig_atomic_t fault_code;

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

int main(void)
{
  uint32_t fw = kernel_get_fw_version();
  int soc = sceKernelGetMainSocId();
  if ((fw & 0xffff0000U) != 0x12700000U || soc != 0x840f60)
    return 1;

  struct timespec stamp = {0};
  if (clock_gettime(CLOCK_REALTIME, &stamp) != 0)
    return 2;
  char path[192], line[256];
  snprintf(path, sizeof(path),
           "/mnt/usb0/PS5-12.70-vmmcall-user-%d-%ld-%ld.txt",
           (int)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return 3;
  snprintf(line, sizeof(line),
           "start,fw=0x%08x,soc=0x%x,cpl=3,command=0x%04" PRIx64 "\n",
           fw, soc, COMMAND);
  if (log_line(fd, line) != 0) {
    close(fd);
    return 4;
  }

  struct sigaction sa = {0};
  sa.sa_sigaction = on_fault;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);

  if (log_line(fd, "before,stage=vmmcall\n") != 0) {
    close(fd);
    return 5;
  }
  if (sigsetjmp(recovery, 1) == 0) {
    uint64_t result = COMMAND;
    __asm__ volatile("vmmcall" : "+a"(result) : : "memory");
    snprintf(line, sizeof(line), "after,stage=vmmcall,result=returned,rax=0x%016"
             PRIx64 "\n", result);
  } else {
    snprintf(line, sizeof(line),
             "after,stage=vmmcall,result=signal,sig=%d,code=%d\n",
             (int)fault_signal, (int)fault_code);
  }
  if (log_line(fd, line) != 0) {
    close(fd);
    return 6;
  }
  if (log_line(fd, "end,complete=1,calls=1\n") != 0) {
    close(fd);
    return 7;
  }
  close(fd);
  printf("12.70 CPL3 VMMCALL probe: %s; log %s\n", line, path);
  return 0;
}
