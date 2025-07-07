# Printf
- checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'libc/'
    Stripped:   No
```      
- everything is protected, ahhhh who cares. we have `printf` in our side


- code
```c
{
    ....
    stack leak
    ...
    read(0, buf, 0x200uLL);
    puts("Here we go!!");
    printf(buf); <--- rop from here
    exit(0);
}
```

- as we can see, a printf chall, we need to leak and loop to main so we can use our leaks
- we have a stack leak so we overwrite return address of printf to point the start of main, we only need to overwrite one byte to go to the start of main
- and in the same time leak libc or smth, bc of this i didnt use `fmt_payload`, i just started manually making my payload

- game plan
    - leak libc, return to main
    - rop to system 

[solve script contains more details](x.py)



[author: T4K1](https://github.com/al-wasmo)
