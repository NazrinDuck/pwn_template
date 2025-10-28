#define _GNU_SOURCE

// #include "./bpf_insn.h"
#include <arpa/inet.h>
#include <fcntl.h>
// #include <keyutils.h>
// #include <linux/if_packet.h>
// #include <linux/userfaultfd.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <threads.h>
#include <unistd.h>

#include "./klog.h"
#include "./kpwn.h"

#define TARGET "xxx.ko"
#define KERNEL_VERSION "6.17.0"

void banner() {
  printf("\n");
  printf(BLUE "==========================================\n" END);
  printf(CYAN "         Linux Kernel-Pwn Exploit         \n" END);
  printf("              by" YELLOW " NazrinDuck\n" END);
  printf("          Kernel Version: " RED KERNEL_VERSION END "\n");
  printf(BLUE "==========================================\n" END);
  printf("\n");
}

void __attribute__((constructor)) init() {
  bind_cpu(0);
  banner();
  adjust_rlimit();
  page_size = sysconf(_SC_PAGESIZE);
  info("page size: %#lx\n", page_size);
}

const char *device = "/dev/";

// NOTE: Linux Kernel exploit template
// Kernel version:
int main() {
  // INFO: Step 0x01: open device
  step("open device");

  save_stat();
  int fd = check(open(device, 2));
  success("device open successfully\n");

  for (;;) {
    sleep(0x100);
  }
  return 0;
}
