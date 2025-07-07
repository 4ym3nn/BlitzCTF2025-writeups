# Misc - Chamber Of Secrets - Writeup

## Step 1: Analyze the File Using Binwalk

We begin by inspecting `file_1` using `binwalk`:

```bash
binwalk file_1
```

Output:
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
57675         0xE14B          Zip archive data, encrypted at least v2.0 to extract, compressed size: 110, uncompressed size: 99, name: ffll44gg
57945         0xE259          End of Zip archive, footer length: 22
```

A ZIP archive is embedded inside the JPEG file at offset `0xE14B`.

---

## Step 2: Extract Embedded Files

We extract the embedded files using:

```bash
binwalk -e file_1
```

This creates a `_file_1.extracted` directory containing the extracted ZIP archive named `0xE14B`.

---

## Step 3: Crack the ZIP Password

The ZIP file is password protected. We use `zip2john` and `john` with the CrackStation wordlist, which can be downloaded from:

[https://download.g0tmi1k.com/wordlists/large/crackstation-human-only.txt.gz](https://download.g0tmi1k.com/wordlists/large/crackstation-human-only.txt.gz)

Steps:

1. Generate the hash for John:

    ```bash
    zip2john 0xE14B.zip > zip_hash.txt
    ```

2. Run John with the wordlist:

    ```bash
    john zip_hash.txt --wordlist=crackstation-human-only.txt
    ```

3. John recovers the password:

    ```
    Password found: exchanged
    ```

---

## Step 4: Extract the ZIP File

Use the password to extract contents:

```bash
unzip -P exchanged ffll44gg
```

This gives a URL:

```
https://lastchamberofsecrect.com/url-decode/base?galf=QmxpdHp7aDFkZDNuXzFuXzdoM19kMzNwX3hEfQ%3D%3D
```

---

## Step 5: Decode the Flag

we notice a base64 encoding message in the parameter `galf` which is `flag` reversed:

```
QmxpdHp7aDFkZDNuXzFuXzdoM19kMzNwX3hEfQ==
```

Decoded result:

```
Blitz{h1dd3n_1n_7h3_d33p_xD}
```

---

## Final Flag

```
Blitz{h1dd3n_1n_7h3_d33p_xD}
```
