# EntropyMixer

- checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'libc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```      

- we have two options
    - entropy_diagnostic();
    - entropy_injection();

- `entropy_diagnostic()` : just xors your input with a random  `entropy` and prints it 
- `entropy_diagnostic()` : a obvious bof, the only catch is that your input gets xored with the random `entropy`
```c
  _BYTE buf[72]; // [rsp+0h] [rbp-50h] BYREF
  ssize_t v2; // [rsp+48h] [rbp-8h]

  puts("\n[+] Injecting entropy into system: ");
  v2 = read(0, buf, 0x1000uLL);
  xor_encrypt((__int64)buf, v2);
  return puts("\n[+] Processing injected entropy...");
```


- so what we have to do is to leak `entropy` by sending `zero bytes`, a ^ 0 = a
- next we `ROP` but we wrap our payload with pwntools `xor(payload,leaked_entropy)`


[solve script contains more details](x.py)

[author: T4K1](https://github.com/al-wasmo)
