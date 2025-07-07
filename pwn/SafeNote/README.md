# SafeNote

- checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'libc/'
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


- standard heap chall with one byte overflow and secomp
- just read [house_of_einherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_einherjar.c)


- recap
    - `leak heap` using, alloc -> free -> alloc -> read
    - overlap chunks (`house_of_einherjar`) and `leak libc` using it
    - controle tcache next pointer to `leak stack`
    - we have `arb read and write` using tcache 
    - so rop
    - i mmaped the heap and jumped to it xD

[solve script contains more details](x.py)


[author: T4K1](https://github.com/al-wasmo)
