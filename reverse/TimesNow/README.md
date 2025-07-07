# TimesNow
- painfull ocaml reverse chall, wasted too much time reading the disassembly but i didnt need that
- its using a `rc4` kinda of modifed stream cipher, and we have enc flag file so we just 
    - fix time using `LD_PRELOAD` trick
    - make the script run on a fake `flag.txt` file, 
    - always add one byte and check if that the `enc` byte is the same as the one in the `original enc flag` in `AA.enc`
    - then move to the next byte


- welp i didnt need unboxed numbers and lxm random number genrator after all

[solve script contains more details](bruteforce.py)


[author: T4K1](https://github.com/al-wasmo)