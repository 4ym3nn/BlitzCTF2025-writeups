## Diff N' Rae

XOR the two images using the following Python script:

```python
with open("Tate_McRae_1.jpg", "rb") as f1, open("Tate_McRae_2.jpg", "rb") as f2:
    b1 = f1.read()
    b2 = f2.read()

diff_chars = [chr(x ^ y) for x, y in zip(b1, b2) if x != y]
print("".join(diff_chars))
```

The output:

```
Th}fq^k ZDFmRl8xU1)3\TNmdUx9
```

We decoded:

- `ZDFmRl8xU1` → `d1fF_1S`
- `TNmdUx9` → `3ful}`

Guessing the middle part gives the final flag:

```
Blitz{d1fF_1S_u53fuL}
```

---

