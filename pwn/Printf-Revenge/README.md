
# Printf-Revenge

- checksec
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'a'
    Stripped:   No
```


- code
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _DWORD v4[2]; // [rsp+8h] [rbp-228h] BYREF
  _QWORD buf[68]; // [rsp+10h] [rbp-220h] BYREF

  buf[67] = __readfsqword(0x28u);
  memset(buf, 0, 0x210uLL);
  buf[64] = 1LL;
  // write stack addr in buffer
  buf[65] = &buf[64]; 
  
  ....
  
  // pie leak
  printf("I feel generous so have this: %p\n", main); 
  putchar(62);

  // offset stack addr written :)
  __isoc99_scanf("%u", v4);
  if ( v4[0] > 0x20u )
  {
    printf("not this again :)");
    exit(0);
  }
  buf[65] += v4[0];
  
  ...

  // fmt
  printf((const char *)buf);
  return 0;
}
```


- solve script is kinda random, but here is the recap
    - overwrite `__stack_chk_fail` with main, then overwrite stack canary with random value using the given `stack pointer` offseted by `24`
    - now we have a loop kinda of, need to always overwrite `canary`
    - leak stack, leak libc using got, then rop. simple


- one problem i encountered, my libc leaks weren't the same as the server, i think they gave us wrong libc version or smth, been fixed later but i solved it before the fix
- bc i had arb read into the got, i leaked a couple of libc addresses from the server and used [libc.rip](https://libc.rip/) to get the right libc 

[solve script contains more details](x.py)



[author: T4K1](https://github.com/al-wasmo)
