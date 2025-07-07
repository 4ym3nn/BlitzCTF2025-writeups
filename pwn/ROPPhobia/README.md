# ROPPhobia
- checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'libc/'
    Stripped:   No
```

- simple c++ heap with a obvious bof vuln
- the idea is, leak libc and heap pointers using kinda of `arb read` into heap
- and then rop using libc, but we have seccomps

```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1b 0xc000003e  if (A != ARCH_X86_64) goto 0029
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x18 0xffffffff  if (A != 0xffffffff) goto 0029
 0006: 0x15 0x16 0x00 0x00000001  if (A == write) goto 0029
 0007: 0x15 0x15 0x00 0x00000002  if (A == open) goto 0029
 0008: 0x15 0x14 0x00 0x00000003  if (A == close) goto 0029

 
 0009: 0x15 0x13 0x00 0x00000009  if (A == mmap) goto 0029
 0010: 0x15 0x12 0x00 0x0000000a  if (A == mprotect) goto 0029
 0011: 0x15 0x11 0x00 0x0000000b  if (A == munmap) goto 0029
 0012: 0x15 0x10 0x00 0x00000012  if (A == pwrite64) goto 0029
 0014: 0x15 0x0e 0x00 0x00000028  if (A == sendfile) goto 0029
 0015: 0x15 0x0d 0x00 0x00000038  if (A == clone) goto 0029
 0016: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0029
 0017: 0x15 0x0b 0x00 0x0000003a  if (A == vfork) goto 0029
 0018: 0x15 0x0a 0x00 0x0000003b  if (A == execve) goto 0029
 0019: 0x15 0x09 0x00 0x0000003e  if (A == kill) goto 0029
 0020: 0x15 0x08 0x00 0x00000101  if (A == openat) goto 0029
 0022: 0x15 0x06 0x00 0x00000128  if (A == pwritev) goto 0029
 0024: 0x15 0x04 0x00 0x00000137  if (A == process_vm_writev) goto 0029
 0025: 0x15 0x03 0x00 0x00000142  if (A == execveat) goto 0029
 0027: 0x15 0x01 0x00 0x00000148  if (A == pwritev2) goto 0029
 0028: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0029: 0x06 0x00 0x00 0x00000000  return KILL

0005: 0x15 0x17 0x00 0x00000000  if (A == read) goto 0029
0013: 0x15 0x0f 0x00 0x00000013  if (A == readv) goto 0029
0021: 0x15 0x07 0x00 0x00000127  if (A == preadv) goto 0029
0023: 0x15 0x05 0x00 0x00000136  if (A == process_vm_readv) goto 0029
0026: 0x15 0x02 0x00 0x00000147  if (A == preadv2) goto 0029

```

- its no problem bc we have the full list of usefull syscalls from  the `Shellphobia` challenge

- so we use 
  - `openat2` to open a file
  - `pread64` to read the file into heap
  - `writev` to write it to `stdout`

[solve script contains more details](x.py)


[author: T4K1](https://github.com/al-wasmo)
