# SimpleNote

- checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'libc/'
```

- its a `fastbin dub` chall, its using calloc to allocate memory, so we cant use the tcache
- and there is use after free, its freeing the memory but not seting pointer to `zero`

- there is hidden option `9999` which can be used to leak `pie`, if we send to `scanf` value of `-`, it will ignore out input and not write in `v1`, leaking the `pie`  

```c
// you get here by sending 9999
unsigned __int64 sub_193C()
{
  void *v1; // [rsp+8h] [rbp-68h] BYREF
  char s[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v3; // [rsp+68h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = &BSS_ADDR;
  puts("enter your name: ");
  fgets(s, 80, stdin);
  puts("enter your age: ");
  __isoc99_scanf("%ld", &v1);  <----- send "-"
  getchar();
  printf("your age: %ld and name: %s\n", v1, s);
  puts("but ... why you here???");
  return v3 - __readfsqword(0x28u);
}
```

- okey we have pie, uaf, and a global pointer array. the plan is obvious. `roping`

[solve script contains more details](x.py)


[author: T4K1](https://github.com/al-wasmo)
