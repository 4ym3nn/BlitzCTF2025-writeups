
## Challenge Analysis

The challenge provides an encrypted file (`flag.txt.enc`) and the source code used for encryption. Looking at the encryption function:

```python
def encrypt_file(file):
    with open(file, 'rb') as f:
        data = f.read()
        f.close()
    key = get_random_bytes(16)
    iv = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    encrypted += key[::-1] + iv[::-1] 
    outfile = file + '.enc'
    with open(outfile, 'wb') as f:
        f.write(encrypted)
        f.close()
```

## Key Observations

1. **AES-CBC encryption** is used with a 16-byte key
2. The code generates an 8-byte IV but **doesn't use it** in the cipher initialization
3. When no IV is provided to `AES.new()`, PyCryptodome generates a random 16-byte IV
4. The encrypted data is appended with: `key[::-1] + iv[::-1]` (reversed key + reversed IV)
5. Since the actual IV used is 16 bytes (not the 8-byte one generated), the tail is 32 bytes total

## Solution Approach

The encrypted file structure is:
- **First 48 bytes**: AES-CBC encrypted data  
- **Next 16 bytes**: Original key (reversed)
- **Last 16 bytes**: Actual IV used (reversed)

### Decryption Steps

1. **Extract components from the 80-byte encrypted data**:
   ```python
   encrypted_data = ciphertext[:-32]  # First 48 bytes
   key_rev = ciphertext[-32:-16]      # Reversed key
   iv_rev = ciphertext[-16:]          # Reversed IV
   ```

2. **Reverse the key and IV**:
   ```python
   key = key_rev[::-1]
   iv = iv_rev[::-1]
   ```

3. **Decrypt using AES-CBC**:
   ```python
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import unpad
   
   cipher = AES.new(key, AES.MODE_CBC, iv=iv)
   plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
   ```

## Flag

```
Blitz{t0p_s3cr3t_l0ckd0wn_1337}
```
