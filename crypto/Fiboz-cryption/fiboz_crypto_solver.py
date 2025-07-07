import sys
from collections import defaultdict

def x7a3(n):
    s = 0
    while n != 1:
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        s += 1
    return s

def precompute_x7a3(max_n):
    table = [0] * (max_n + 1)
    for n in range(2, max_n + 1):
        x = n
        steps = 0
        while x != 1:
            if x % 2 == 0:
                x = x // 2
            else:
                x = 3 * x + 1
            steps += 1
            if x > max_n:
                break
        table[n] = steps
    return table

def build_k_to_n(x7a3_table):
    k_to_n = defaultdict(list)
    for n, k in enumerate(x7a3_table):
        k_to_n[k].append(n)
    return k_to_n

def y4f2(length, a, b):
    seq = [a, b]
    for _ in range(length - 2):
        seq.append(seq[-1] + seq[-2])
    return seq

def decrypt(ciphertext, key):
    return bytes([ciphertext[i] ^ (key[i % len(key)] % 256) for i in range(len(ciphertext))])

def recover_a_b(ciphertext, plaintext_start, max_n=10000000):
    x7a3_table = precompute_x7a3(max_n)
    k_to_n = build_k_to_n(x7a3_table)

    k = [plaintext_start[i] ^ ciphertext[i] for i in range(len(plaintext_start))]
    print(f"Recovered key bytes: {k}")

    possible_a = k_to_n.get(k[0], [])
    possible_b = k_to_n.get(k[1], [])

    solutions = []
    for a in possible_a:
        for b in possible_b:
            if (a + b) > max_n:
                continue
            if x7a3_table[a + b] != k[2]:
                continue
            if (a + 2 * b) > max_n:
                continue
            if x7a3_table[a + 2 * b] != k[3]:
                continue
            if (2 * a + 3 * b) > max_n:
                continue
            if x7a3_table[2 * a + 3 * b] != k[4]:
                continue
            if (3 * a + 5 * b) > max_n:
                continue
            if x7a3_table[3 * a + 5 * b] != k[5]:
                continue

            l = len(ciphertext)
            f = y4f2(l, a, b)
            c = [x7a3(n) for n in f]
            decrypted = decrypt(ciphertext, c)
            try:
                decrypted_text = decrypted.decode('ascii')
                if decrypted_text.startswith("Blitz{"):
                    solutions.append((a, b))
                    print(f"Valid solution found: a={a}, b={b}")
                    print(f"Decrypted text: {decrypted_text}")
            except UnicodeDecodeError:
                continue

    return solutions

if __name__ == "__main__":
    with open('output.enc', 'rb') as f:
        ciphertext = f.read()

    plaintext_start = b"Blitz{"
    if len(ciphertext) < len(plaintext_start):
        print("Ciphertext too short!")
        sys.exit(1)

    solutions = recover_a_b(ciphertext, plaintext_start)

    if not solutions:
        print("No valid solutions found. Try increasing max_n.")
    else:
        print("\nValid (a, b) pairs:")
        for a, b in solutions:
            print(f"a={a}, b={b}")
