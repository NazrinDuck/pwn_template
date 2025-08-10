#ifndef __KPWN_H
#define __KPWN_H

#include <stdint.h>
#include <stdlib.h>

#define TTY_MAGIC 0x200005401

#define KERNCALL __attribute__((regparm(3)))

extern void *(*prepare_kernel_cred)(void *)KERNCALL;
extern void (*commit_creds)(void *) KERNCALL;

extern uint64_t user_cs, user_ss, user_rflags, user_sp;
extern uint64_t kernel_base, canary;
extern size_t page_size;

extern void dump_hex(const char *__restrict hex, size_t len);
extern uint64_t calc(uint64_t addr);
extern void register_userfaultfd(void *addr, uint64_t len,
                                 void *(*handler)(void *));
#ifndef MUSL
extern void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                       unsigned int frame_size,
                                       unsigned int block_nr,
                                       unsigned int sizeof_priv,
                                       unsigned int timeout);

extern int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                               unsigned int block_nr, unsigned int sizeof_priv,
                               int timeout);

extern int pagealloc_pad(int count, int size);
#endif

// struct msg_msg
//
struct list_head {
  uint64_t next;
  uint64_t prev;
};

struct msg_msg {
  struct list_head m_list;
  uint64_t m_type;
  uint64_t m_ts;
  uint64_t next;
  uint64_t security;
};

struct msg_msgseg {
  uint64_t next;
};

extern int get_msg_queue(void);
extern int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp);
extern int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp);
extern int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp);
extern void build_msg(struct msg_msg *msg, uint64_t m_list_next,
                      uint64_t m_list_prev, uint64_t m_type, uint64_t m_ts,
                      uint64_t next, uint64_t security);

extern void __attribute__((naked)) save_stat();
extern void templine();
extern void bind_cpu(int core);
extern void unshare_setup();

extern uint64_t leak_from_notes();

extern void pt_reg(int fd, char *buffer);

extern void get_flag();
extern void get_flag_nf();
extern void __attribute__((noreturn)) shell();
extern void shell_noerr();

extern void fork_to_root();
extern void adjust_rlimit();

#endif // !__KPWN_H
